package main

import (
  "bufio"
  "database/sql"
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

// set limit to -1 (or anything < 0) to read all lines
func encryptAndInsertAll(db *sql.DB, path string, limit, offset int) (int64, int, []string, error) {
  totalEncryptionTime := int64(0)
  numEncryptions := 0
  failures := []string{}
  file, err := os.Open(path)
  if err != nil {
    return totalEncryptionTime, numEncryptions, failures, err
  }
  defer file.Close()
  scanner := bufio.NewScanner(file)
  lineCount := 0
  for (limit < 0 || lineCount < limit + offset) && scanner.Scan() {
    lineCount += 1
    if lineCount < offset {
      continue
    }
    line := scanner.Text()
    username, password, err := parseCredential(line)
    if err != nil {
      failures = append(failures, line)
    } else {
      credHash, execTime := runArgon2id([]byte(password), []byte(username), 1, 64*1024, 8, 64)
      totalEncryptionTime += execTime.Nanoseconds()
      numEncryptions += 1
      _, err := db.Exec("INSERT INTO cred_hash_1_64_8_64_test (hash) VALUES (?)", credHash)
      if err != nil {
        failures = append(failures, line)
      }
      rows, err := db.Query("SELECT count FROM pw_data_test WHERE pw='?' LIMIT 1", password)
      if err == nil {
        if rows.Next() {
          _, err := db.Exec("UPDATE pw_data_test SET count = count + 1 WHERE pw='?'", password)
          if err != nil {

          }
        } else {
          length := len(password)
          hasLetters, _ := regexp.MatchString("[a-z]", password)
          hasNumbers, _ := regexp.MatchString("[0-9]", password)
          hasSymbols, _ := regexp.MatchString("[^a-z0-9]", password)
          var let int
          var num int
          var sym int
          if hasLetters {
            let = 1
          }
          if hasNumbers {
            num = 1
          }
          if hasSymbols {
            sym = 1
          }
          _, err := db.Exec("INSERT INTO pw_data_test (pw, count, len, let, num, sym) VALUES ('?', 1, ?, b'?', b'?', b'?')", password, length, let, num, sym)
          if err != nil {

          }
        }
      }
    }
  }
  if err := scanner.Err(); err != nil {
    fmt.Printf("Invalid input: %s\n", err)
  }
  return totalEncryptionTime, numEncryptions, failures, nil
}

func getDB() (*sql.DB, error) {
  db, err := sql.Open("mysql", getDSN())
  return db, err
}

func getDSN() string {
  return os.Getenv("MYSQL_USER") + ":" + os.Getenv("MYSQL_PW") + "@/ccds"
}

func parseCredential(cred string) (string, string, error) {
  if matched, err := regexp.MatchString("^[^\\t]+\\t[^\\t]+$", cred); err != nil || !matched {
    return "", "", errors.New("Unable to parse credential " + cred)
  }
  result := strings.Split(cred, "\t")
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
          _, execTime := runArgon2id([]byte(password), []byte(username), 1, 64*1024, 8, 64)
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

func runArgon2id(password, salt []byte, iterations, memory uint32, threads uint8, keyLen uint32) ([]byte, time.Duration) {
  start := time.Now()
  key := argon2.IDKey(password, salt, iterations, memory, threads, keyLen)
  execTime := time.Since(start)
  return key, execTime
}

func searchHash(db *sql.DB, hash []byte) (bool, error) {
  rows, err := db.Query("SELECT hash FROM hash_test WHERE hash = ? LIMIT 1", hash)
  if err != nil {
    return false, err
  }
  defer rows.Close()
  if rows.Next() {
    return true, nil
  }
  return false, nil
}

func main() {
  db, err := getDB()
  if err != nil {
    log.Fatal(err)
  }
  defer db.Close()
  err = db.Ping()
  if err != nil {
    log.Fatal(err)
  }
  start := time.Now()
  totalEncryptionTime, numEncryptions, failures, err := encryptAndInsertAll(db, "./data/data.tsv", 1000, 0)
  // totalEncryptionTime, numEncryptions := readAllFiles("./data", 5)
  fmt.Println(numEncryptions, "credentials read, encrypted, and inserted in", time.Since(start))
  avgDur, err := time.ParseDuration(strconv.FormatInt(totalEncryptionTime / int64(numEncryptions), 10) + "ns")
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("Average argon2id run time:", avgDur)
  if len(failures) > 0 {
    
  }
}
