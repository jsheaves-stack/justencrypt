use rusqlite_migration::{Migrations, M};

/// Every schema change, in order. A user's database is brought up to date
/// each time it is opened.
pub fn get_migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(
        r#"
                CREATE TABLE IF NOT EXISTS folders (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    parent_folder_id INTEGER,
                    name TEXT NOT NULL,
                    total_folder_size BIGINT NOT NULL DEFAULT 0,
                    total_file_count BIGINT NOT NULL DEFAULT 0,
                    total_folder_count BIGINT NOT NULL DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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

                CREATE TABLE IF NOT EXISTS active_uploads (
                    upload_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    encoded_file_name TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );

                INSERT OR IGNORE INTO folders (id, parent_folder_id, name) VALUES (1, NULL, 'ROOT');

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

                CREATE TRIGGER folders_after_update_parent
                AFTER UPDATE ON folders
                WHEN OLD.parent_folder_id IS NOT NEW.parent_folder_id
                BEGIN
                    UPDATE folders
                    SET total_folder_size = total_folder_size - OLD.total_folder_size,
                        total_file_count = total_file_count - OLD.total_file_count,
                        total_folder_count = total_folder_count - OLD.total_folder_count - 1
                    WHERE id IN (
                        WITH RECURSIVE ParentFolders AS (
                            SELECT OLD.parent_folder_id AS id UNION ALL
                            SELECT f.parent_folder_id FROM folders f INNER JOIN ParentFolders pf ON f.id = pf.id WHERE f.parent_folder_id IS NOT NULL
                        ) SELECT id FROM ParentFolders
                    );
                    UPDATE folders
                    SET total_folder_size = total_folder_size + NEW.total_folder_size,
                        total_file_count = total_file_count + NEW.total_file_count,
                        total_folder_count = total_folder_count + NEW.total_folder_count + 1
                    WHERE id IN (
                        WITH RECURSIVE ParentFolders AS (
                            SELECT NEW.parent_folder_id AS id UNION ALL
                            SELECT f.parent_folder_id FROM folders f INNER JOIN ParentFolders pf ON f.id = pf.id WHERE f.parent_folder_id IS NOT NULL
                        ) SELECT id FROM ParentFolders
                    );
                END;

                CREATE TRIGGER files_after_update_timestamp
                AFTER UPDATE ON files
                FOR EACH ROW
                WHEN NEW.updated_at = OLD.updated_at
                BEGIN
                    UPDATE files SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
                END;

                CREATE TRIGGER folders_after_update_timestamp
                AFTER UPDATE ON folders
                FOR EACH ROW
                WHEN NEW.updated_at = OLD.updated_at
                BEGIN
                    UPDATE folders SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
                END;

                CREATE TRIGGER prevent_root_folder_update
                BEFORE UPDATE ON folders
                WHEN OLD.id = 1 AND (OLD.name != NEW.name OR NEW.parent_folder_id IS NOT NULL OR NEW.id != 1)
                BEGIN
                    SELECT RAISE(ABORT, 'Cannot rename or move ROOT folder');
                END;

                CREATE TRIGGER prevent_root_folder_delete
                BEFORE DELETE ON folders
                WHEN OLD.id = 1
                BEGIN
                    SELECT RAISE(ABORT, 'Cannot delete ROOT folder');
                END;
            "#,
    )])
}
