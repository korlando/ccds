package server

import (
  "database/sql"
  _ "github.com/go-sql-driver/mysql"
)

const CredHashTable = "cred_hash_1_64_8_64"
const CredHashTableCreate = `
  CREATE TABLE IF NOT EXISTS ` + CredHashTable + ` (
    hash varbinary(64) NOT NULL,
    checked int(11) DEFAULT '0',
    PRIMARY KEY (hash),
    UNIQUE KEY hash_UNIQUE (hash)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
`

func CreateTables(db *sql.DB) (err error) {
  _, err = db.Exec(CredHashTableCreate)
  if err != nil {
    return
  }
  return
}
