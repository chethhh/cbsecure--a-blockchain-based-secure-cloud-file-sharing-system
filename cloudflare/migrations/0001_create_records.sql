CREATE TABLE IF NOT EXISTS cb_secure_records (
  collection TEXT NOT NULL,
  record_key TEXT NOT NULL,
  payload TEXT NOT NULL,
  PRIMARY KEY (collection, record_key)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS cb_secure_file_chunks (
  storage_key TEXT NOT NULL,
  chunk_index INTEGER NOT NULL,
  payload BLOB NOT NULL,
  PRIMARY KEY (storage_key, chunk_index)
) WITHOUT ROWID;
