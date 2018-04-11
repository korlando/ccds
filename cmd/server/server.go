package main

import (
  "database/sql"
  "flag"
  "log"
  "strconv"
  _ "github.com/go-sql-driver/mysql"
  "ccds/src/app"
  "ccds/src/factory"
)

func main() {
  var port int
  var production bool
  flag.IntVar(&port, "port", 8080, "Specify the port to run the server on.")
  flag.BoolVar(&production, "production", false, "Sets the server to production mode.")
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
  err = db.Ping()
  if err != nil {
    log.Fatal(err)
  }
  a := app.App{}
  a.Initialize(db)
  a.Run(":" + strconv.Itoa(port))
}
