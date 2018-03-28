package main

import (
  "bytes"
  "database/sql"
  "encoding/hex"
  "fmt"
  "os"
  "time"
  "golang.org/x/crypto/argon2"
  _ "github.com/go-sql-driver/mysql"
)

func getArgon2idExecTime(password, salt []byte, iterations, memory uint32, threads uint8, keyLen uint32) (time.Duration, string) {
  start := time.Now()
  key := argon2.IDKey(password, salt, iterations, memory, threads, keyLen)
  keyHex := hex.EncodeToString(key)
  execTime := time.Since(start)
  return execTime, keyHex
}

func getDB() (*sql.DB, error) {
  db, err := sql.Open("mysql", getDSN())
  return db, err
}

func getDSN() string {
  var dataSourceName bytes.Buffer
  dataSourceName.WriteString(os.Getenv("MYSQL_USER"))
  dataSourceName.WriteString(":")
  dataSourceName.WriteString(os.Getenv("MYSQL_PW"))
  dataSourceName.WriteString("@localhost:3306/mysql")
  return dataSourceName.String()
}

func main() {
  execTime, key := getArgon2idExecTime([]byte("password"), []byte("abc123"), 1, 32*1024, 2, 256)
  fmt.Println(execTime)
  fmt.Println(key)
  db, err := getDB()
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println(db)
}
