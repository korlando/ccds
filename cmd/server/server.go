package main

import (
  "database/sql"
  "flag"
  "fmt"
  "log"
  "strconv"
  _ "github.com/go-sql-driver/mysql"
  "ccds/server"
)

func main() {
  var port int
  var production bool
  var create bool
  flag.IntVar(&port, "port", 8080, "Specify the port to run the server on.")
  flag.BoolVar(&production, "production", false, "Sets the server to production mode; uses production DB.")
  flag.BoolVar(&create, "c", false, "Run table creation queries.")
  flag.Parse()
  var db *sql.DB
  var err error
  if production {
    db, err = server.GetProdDB()
  } else {
    db, err = server.GetDevDB()
  }
  if err != nil {
    log.Fatal(err)
  }
  err = db.Ping()
  if err != nil {
    log.Fatal(err)
  }
  if create {
    // attempt to create the tables
    fmt.Println("Creating tables...")
    err = server.CreateTables(db)
    if err != nil {
      log.Fatal(err)
    }
  }
  a := server.App{}
  a.Initialize(db)
  a.Run(":" + strconv.Itoa(port))
}
