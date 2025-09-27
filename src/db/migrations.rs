use rusqlite_migration::{Migrations, M};

pub fn get_migrations() -> Migrations<'static> {
    Migrations::new(vec![M::up(
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
                buffer_size INTEGER NOT NULL,
                nonce_size INTEGER NOT NULL,
                salt_size INTEGER NOT NULL,
                tag_size INTEGER NOT NULL,
                FOREIGN KEY (parent_folder_id) REFERENCES folders(id),
                UNIQUE(parent_folder_id, name),
                UNIQUE(encoded_name)
            );

            CREATE TABLE IF NOT EXISTS thumbnails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encoded_name TEXT NOT NULL,
                file_id INTEGER,
                key BLOB NOT NULL,
                buffer_size INTEGER NOT NULL,
                nonce_size INTEGER NOT NULL,
                salt_size INTEGER NOT NULL,
                tag_size INTEGER NOT NULL,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
                UNIQUE(encoded_name)
            );

            INSERT OR IGNORE INTO folders (id, parent_folder_id, name) VALUES (1, NULL, 'ROOT');
        "#,
    )])
}
