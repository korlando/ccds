package main

import (
  "bufio"
  "bytes"
  "database/sql"
  "encoding/hex"
  "errors"
  "fmt"
  "io/ioutil"
  "log"
  "os"
  "regexp"
  "strings"
  "time"
  "golang.org/x/crypto/argon2"
  _ "github.com/go-sql-driver/mysql"
)

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

func parseCredential(cred string) (string, string, error) {
  if matched, err := regexp.MatchString("^[^\\:]+:[^\\:]+$", cred); err != nil || !matched {
    return "", "", errors.New("Unable to parse credential " + cred)
  }
  result := strings.Split(cred, ":")
  return result[0], result[1], nil
}

func readAllFiles(from string) {
  files, err := ioutil.ReadDir(from)
  if err != nil {
    log.Fatal(err)
  }
  for _, fileInfo := range files {
    path := from + "/" + fileInfo.Name()
    if fileInfo.IsDir() {
      readAllFiles(path)
    } else {
      file, err := os.Open(path)
      if err != nil {
        log.Fatal(err)
      }
      defer file.Close()
      scanner := bufio.NewScanner(file)
      for scanner.Scan() {
        username, password, parseErr := parseCredential(scanner.Text())
        if parseErr != nil {
          fmt.Printf("Parsing error: %s\n", parseErr)
        } else {
          fmt.Println("USERNAME: " + username + "   PASSWORD: " + password)
        }
      }
      if err := scanner.Err(); err != nil {
        fmt.Printf("Invalid input: %s\n", err)
      }
    }
  }
}

func runArgon2id(password, salt []byte, iterations, memory uint32, threads uint8, keyLen uint32) (string, time.Duration) {
  start := time.Now()
  key := argon2.IDKey(password, salt, iterations, memory, threads, keyLen)
  keyHex := hex.EncodeToString(key)
  execTime := time.Since(start)
  return keyHex, execTime
}

func main() {
  // key, execTime := runArgon2id([]byte("password"), []byte("abc123"), 1, 32*1024, 2, 256)
  // fmt.Println(execTime)
  // fmt.Println(key)
  // db, err := getDB()
  // if err != nil {
  //   fmt.Println(err)
  // }
  // fmt.Println(db)
  readAllFiles("./data")
}
