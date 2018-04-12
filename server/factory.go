package server

import (
  "database/sql"
  "os"
)

type CredHash struct {
  Hash  string `json:"hash"`
  Count int
}

func GetDevDB() (*sql.DB, error) {
  return sql.Open("mysql", os.Getenv("CCDS_DEV_DB_USER") + ":" + os.Getenv("CCDS_DEV_DB_PW") + "@/" + os.Getenv("CCDS_DEV_DB_NAME"))
}

func GetProdDB() (*sql.DB, error) {
  return sql.Open("mysql", os.Getenv("CCDS_DB_USER") + ":" + os.Getenv("CCDS_DB_PW") + "@" + os.Getenv("CCDS_DB_ADDRESS") + "/" + os.Getenv("CCDS_DB_NAME"))
}

func SearchCredHash(db *sql.DB, hash []byte) (bool, error) {
  var exists bool
  err := db.QueryRow("SELECT EXISTS(SELECT * FROM " + CredHashTable + " WHERE hash=? LIMIT 1)", hash).Scan(&exists)
  if err != nil {
    return false, err
  }
  return exists, nil
}
