package server

import (
  "database/sql"
  "os"
)

const CreateDB = "CREATE SCHEMA ccds DEFAULT CHARACTER SET utf8;"

func GetDevDB() (*sql.DB, error) {
  return sql.Open("mysql", os.Getenv("CCDS_DEV_DB_USER") + ":" + os.Getenv("CCDS_DEV_DB_PW") + "@/" + os.Getenv("CCDS_DEV_DB_NAME"))
}

func GetProdDB() (*sql.DB, error) {
  return sql.Open("mysql", os.Getenv("CCDS_DB_USER") + ":" + os.Getenv("CCDS_DB_PW") + "@" + os.Getenv("CCDS_DB_ADDRESS") + "/" + os.Getenv("CCDS_DB_NAME"))
}
