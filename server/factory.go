package server

import (
  "database/sql"
)

type CredHash struct {
  Hash  string `json:"hash"`
  Count int
}

func SearchCredHash(db *sql.DB, hash []byte) (bool, error) {
  var exists bool
  err := db.QueryRow("SELECT EXISTS(SELECT * FROM " + CredHashTable + " WHERE hash=? LIMIT 1)", hash).Scan(&exists)
  if err != nil {
    return false, err
  }
  return exists, nil
}
