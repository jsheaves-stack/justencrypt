use rusqlite_migration::{Migrations, M};

pub fn get_migrations() -> Migrations<'static> {
    Migrations::new(vec![
        M::up(
            r#"
                CREATE TABLE IF NOT EXISTS folders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_folder_id INTEGER,
                    name TEXT NOT NULL,
                    FOREIGN KEY (parent_folder_id) REFERENCES folders(id),
                    UNIQUE(parent_folder_id, name)
                );

                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_folder_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    encoded_name TEXT NOT NULL,
                    file_extension TEXT,
                    key BLOB NOT NULL,
                    encryption_version INTEGER NOT NULL DEFAULT 1,
                    total_size BIGINT NOT NULL DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (parent_folder_id) REFERENCES folders(id),
                    UNIQUE(parent_folder_id, name),
                    UNIQUE(encoded_name)
                );

                INSERT OR IGNORE INTO folders (id, parent_folder_id, name) VALUES (1, NULL, 'ROOT');
            "#,
        ),
        M::up(
            r#"
                CREATE TABLE IF NOT EXISTS new_folders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_folder_id INTEGER,
                    name TEXT NOT NULL,
                    total_folder_size BIGINT NOT NULL DEFAULT 0,
                    total_file_count BIGINT NOT NULL DEFAULT 0,
                    total_folder_count BIGINT NOT NULL DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (parent_folder_id) REFERENCES new_folders(id),
                    UNIQUE(parent_folder_id, name)
                );

                INSERT INTO new_folders (id, parent_folder_id, name)
                SELECT id, parent_folder_id, name FROM folders;

                DROP TABLE folders;
                ALTER TABLE new_folders RENAME TO folders;

                UPDATE folders 
                SET 
                    total_folder_size = COALESCE((
                        WITH RECURSIVE SubFolders AS (
                            SELECT folders.id AS id
                            UNION ALL
                            SELECT f.id FROM folders f
                            INNER JOIN SubFolders sf ON f.parent_folder_id = sf.id
                        )
                        SELECT SUM(files.total_size)
                        FROM files
                        WHERE files.parent_folder_id IN (SELECT id FROM SubFolders)
                    ), 0),
                    total_file_count = (
                        WITH RECURSIVE SubFolders AS (
                            SELECT folders.id AS id
                            UNION ALL
                            SELECT f.id FROM folders f
                            INNER JOIN SubFolders sf ON f.parent_folder_id = sf.id
                        )
                        SELECT COUNT(files.id)
                        FROM files
                        WHERE files.parent_folder_id IN (SELECT id FROM SubFolders)
                    ),
                    total_folder_count = (
                        WITH RECURSIVE SubFolders AS (
                            SELECT folders.id AS id
                            UNION ALL
                            SELECT f.id FROM folders f
                            INNER JOIN SubFolders sf ON f.parent_folder_id = sf.id
                        )
                        SELECT COUNT(id) FROM SubFolders WHERE id != folders.id
                    );

                CREATE TRIGGER files_after_insert
                AFTER INSERT ON files
                BEGIN
                    UPDATE folders
                    SET total_folder_size = total_folder_size + NEW.total_size,
                        total_file_count = total_file_count + 1
                    WHERE id IN (
                        WITH RECURSIVE ParentFolders AS (
                            SELECT NEW.parent_folder_id AS id
                            UNION ALL
                            SELECT f.parent_folder_id FROM folders f
                            INNER JOIN ParentFolders pf ON f.id = pf.id
                            WHERE f.parent_folder_id IS NOT NULL
                        )
                        SELECT id FROM ParentFolders
                    );
                END;

                CREATE TRIGGER files_after_delete
                AFTER DELETE ON files
                BEGIN
                    UPDATE folders
                    SET total_folder_size = total_folder_size - OLD.total_size,
                        total_file_count = total_file_count - 1
                    WHERE id IN (
                        WITH RECURSIVE ParentFolders AS (
                            SELECT OLD.parent_folder_id AS id
                            UNION ALL
                            SELECT f.parent_folder_id FROM folders f
                            INNER JOIN ParentFolders pf ON f.id = pf.id
                            WHERE f.parent_folder_id IS NOT NULL
                        )
                        SELECT id FROM ParentFolders
                    );
                END;

                CREATE TRIGGER files_after_update
                AFTER UPDATE ON files
                WHEN OLD.parent_folder_id != NEW.parent_folder_id OR OLD.total_size != NEW.total_size
                BEGIN
                    UPDATE folders
                    SET total_folder_size = total_folder_size - OLD.total_size,
                        total_file_count = total_file_count - 1
                    WHERE id IN (
                        WITH RECURSIVE ParentFolders AS (
                            SELECT OLD.parent_folder_id AS id UNION ALL
                            SELECT f.parent_folder_id FROM folders f INNER JOIN ParentFolders pf ON f.id = pf.id WHERE f.parent_folder_id IS NOT NULL
                        ) SELECT id FROM ParentFolders
                    );
                    UPDATE folders
                    SET total_folder_size = total_folder_size + NEW.total_size,
                        total_file_count = total_file_count + 1
                    WHERE id IN (
                        WITH RECURSIVE ParentFolders AS (
                            SELECT NEW.parent_folder_id AS id UNION ALL
                            SELECT f.parent_folder_id FROM folders f INNER JOIN ParentFolders pf ON f.id = pf.id WHERE f.parent_folder_id IS NOT NULL
                        ) SELECT id FROM ParentFolders
                    );
                END;

                CREATE TRIGGER folders_after_insert
                AFTER INSERT ON folders
                WHEN NEW.parent_folder_id IS NOT NULL
                BEGIN
                    UPDATE folders
                    SET total_folder_count = total_folder_count + 1
                    WHERE id IN (
                        WITH RECURSIVE ParentFolders AS (
                            SELECT NEW.parent_folder_id AS id
                            UNION ALL
                            SELECT f.parent_folder_id FROM folders f
                            INNER JOIN ParentFolders pf ON f.id = pf.id
                            WHERE f.parent_folder_id IS NOT NULL
                        )
                        SELECT id FROM ParentFolders
                    );
                END;

                CREATE TRIGGER folders_after_delete
                AFTER DELETE ON folders
                WHEN OLD.parent_folder_id IS NOT NULL
                BEGIN
                    UPDATE folders
                    SET total_folder_count = total_folder_count - 1
                    WHERE id IN (
                        WITH RECURSIVE ParentFolders AS (
                            SELECT OLD.parent_folder_id AS id
                            UNION ALL
                            SELECT f.parent_folder_id FROM folders f
                            INNER JOIN ParentFolders pf ON f.id = pf.id
                            WHERE f.parent_folder_id IS NOT NULL
                        )
                        SELECT id FROM ParentFolders
                    );
                END;
            "#,
        ),
    ])
}
