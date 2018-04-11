package factory

import (
  "database/sql"
  "os"
)

type CredHash struct {
  Hash string `json:"hash"`
  Count int
}

const credHashTable = "cred_hash_1_64_8_64"

func GetDevDB() (*sql.DB, error) {
  return sql.Open("mysql", os.Getenv("CCDS_DEV_DB_USER") + ":" + os.Getenv("CCDS_DEV_DB_PW") + "@/" + os.Getenv("CCDS_DEV_DB_NAME"))
}

func GetProdDB() (*sql.DB, error) {
  return sql.Open("mysql", os.Getenv("CCDS_DB_USER") + ":" + os.Getenv("CCDS_DB_PW") + "@" + os.Getenv("CCDS_DB_ADDRESS") + "/" + os.Getenv("CCDS_DB_NAME"))
}

func SearchCredHash(db *sql.DB, hash []byte) (bool, error) {
  var exists bool
  err := db.QueryRow("SELECT EXISTS(SELECT * FROM " + credHashTable + " WHERE hash=? LIMIT 1)", hash).Scan(&exists)
  if err != nil {
    return false, err
  }
  return exists, nil
}
