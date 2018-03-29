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
  "strconv"
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

func readAllFiles(from string, lineLimit int) (int64, int) {
  totalEncryptionTime := int64(0)
  numEncryptions := 0
  files, err := ioutil.ReadDir(from)
  if err != nil {
    log.Fatal(err)
  }
  for _, fileInfo := range files {
    path := from + "/" + fileInfo.Name()
    if fileInfo.IsDir() {
      subTotalEncryptionTime, subNumEncryptions := readAllFiles(path, lineLimit)
      totalEncryptionTime += subTotalEncryptionTime
      numEncryptions += subNumEncryptions
    } else {
      file, err := os.Open(path)
      if err != nil {
        log.Fatal(err)
      }
      defer file.Close()
      scanner := bufio.NewScanner(file)
      count := 0
      var limit int
      if lineLimit < 0 {
        limit = 1
      } else {
        limit = lineLimit
      }
      for count < limit && scanner.Scan() {
        username, password, parseErr := parseCredential(scanner.Text())
        if parseErr != nil {
          fmt.Printf("Parsing error: %s\n", parseErr)
        } else {
          _, execTime := runArgon2id([]byte(password), []byte(username), 1, 32*1024, 2, 256)
          totalEncryptionTime += execTime.Nanoseconds()
          numEncryptions += 1
        }
        if lineLimit >= 0 {
          count += 1
        }
      }
      if err := scanner.Err(); err != nil {
        fmt.Printf("Invalid input: %s\n", err)
      }
    }
  }
  return totalEncryptionTime, numEncryptions
}

func runArgon2id(password, salt []byte, iterations, memory uint32, threads uint8, keyLen uint32) (string, time.Duration) {
  start := time.Now()
  key := argon2.IDKey(password, salt, iterations, memory, threads, keyLen)
  keyHex := hex.EncodeToString(key)
  execTime := time.Since(start)
  return keyHex, execTime
}

func main() {
  // db, err := getDB()
  // if err != nil {
  //   log.Fatal(err)
  // }
  // fmt.Println(db)
  start := time.Now()
  totalEncryptionTime, numEncryptions := readAllFiles("./data", 10)
  fmt.Println(numEncryptions, "credentials read and encrypted in", time.Since(start))
  avgDur, err := time.ParseDuration(strconv.FormatInt(totalEncryptionTime / int64(numEncryptions), 10) + "ns")
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("Average argon2id run time:", avgDur)
}
