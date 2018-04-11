package main

import (
  "database/sql"
  "flag"
  "fmt"
  "log"
  _ "github.com/go-sql-driver/mysql"
  "ccds/src/factory"
)

const credhashTableCreationQuery = `
  CREATE TABLE IF NOT EXISTS cred_hash_1_64_8_64 (
    hash varbinary(64) NOT NULL,
    checked int(11) DEFAULT '0',
    PRIMARY KEY (hash),
    UNIQUE KEY hash_UNIQUE (hash)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
`

func main() {
  var create bool
  var production bool
  flag.BoolVar(&create, "c", false, "Run table creation queries.")
  flag.BoolVar(&production, "production", false, "Run table queries on production DB.")
  flag.Parse()
  var db *sql.DB
  var err error
  if production {
    db, err = factory.GetProdDB()
  } else {
    db, err = factory.GetDevDB()
  }
  if err != nil {
    log.Fatal(err)
  }
  if create {
    // attempt to create the tables
    fmt.Println("Creating credhash table...")
    _, err = db.Exec(credhashTableCreationQuery)
    if err != nil {
      fmt.Println("Error creating credhash table:")
      log.Fatal(err)
    }
  }
}
