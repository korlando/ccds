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
  "ccds/server"
)

const CredentialTable = server.CredHashTable
const PasswordDataTable = "pw_data"

const ParseFailed = "Parse"
const CredInsertFailed = "CredInsert"
const CredDeleteFailed = "CredDelete"
const IncrementFailed = "Increment"
const PwInsertFailed = "PwInsert"

const DataPath = "../../data/data.tsv"
const FailuresFilePath = "../../data/failures.txt"
const TempFailuresFilePath = "../../data/failures.tmp.txt"

const dupeRegexp = "^Error 1062: Duplicate entry.+$"

type failure struct {
  line string
  desc string
  err error
}

func analyzePassword(db *sql.DB, password string) (failure, error) {
  var fail failure
  rows, err := db.Query("SELECT count FROM " + PasswordDataTable + " WHERE pw=? LIMIT 1", password)
  if err == nil {
    defer rows.Close()
    if rows.Next() {
      _, err := db.Exec("UPDATE " + PasswordDataTable + " SET count = count + 1 WHERE pw=?", password)
      if err != nil {
        return failure{password, IncrementFailed, err}, err
      }
    } else {
      length := len(password)
      hasLower, _ := regexp.MatchString("[a-z]", password)
      hasUpper, _ := regexp.MatchString("[A-Z]", password)
      hasNumbers, _ := regexp.MatchString("[0-9]", password)
      hasSymbols, _ := regexp.MatchString("[^a-zA-Z0-9]", password)
      var low int
      var up int
      var num int
      var sym int
      if hasLower {
        low = 1
      }
      if hasUpper {
        up = 1
      }
      if hasNumbers {
        num = 1
      }
      if hasSymbols {
        sym = 1
      }
      _, err := db.Exec("INSERT INTO " + PasswordDataTable + " (pw, count, len, low, up, num, sym) VALUES (?, 1, ?, ?, ?, ?, ?)", password, length, low, up, num, sym)
      if err != nil {
        return failure{password, PwInsertFailed, err}, err
      }
    }
  }
  return fail, nil
}

func checkDB(db *sql.DB) {
  err := db.Ping()
  if err != nil {
    log.Fatal(err)
  }
}

func cleanUpFailures(path string) {
  failureFile, err := os.Open(path)
  if err != nil {
    log.Fatal(err)
  }
  defer failureFile.Close()
  newFile, err := os.Create(TempFailuresFilePath)
  if err != nil {
    log.Fatal(err)
  }
  defer newFile.Close()
  scanner := bufio.NewScanner(failureFile)
  writer := bufio.NewWriter(newFile)
  for scanner.Scan() {
    line := scanner.Text()
    vals := strings.Split(line, "\t")
    isDupeEntry, _ := regexp.MatchString(dupeRegexp, vals[1])
    if vals[0] != CredInsertFailed || (vals[0] == CredInsertFailed && !isDupeEntry) {
      writer.WriteString(line + "\n")
    }
  }
  writer.Flush()
  failureFile.Close()
  newFile.Close()
  err = os.Rename(TempFailuresFilePath, path)
  if err != nil {
    log.Fatal(err)
  }
}

func correctUpperCase(db *sql.DB, limit, offset int) ([]failure, error) {
  failures := []failure{}
  file, err := os.Open(DataPath)
  if err != nil {
    return failures, err
  }
  defer file.Close()
  scanner := bufio.NewScanner(file)
  lineCount := 0
  for (limit < 0 || lineCount < limit + offset) && scanner.Scan() {
    lineCount += 1
    if lineCount < offset {
      continue
    }
    line := strings.TrimSpace(scanner.Text())
    username, password, err := parseCredential(line)
    if err == nil {
      matched, err := regexp.MatchString("[A-Z]", username)
      if err == nil && matched {
        // remove the upper case version
        upperCredHash, _ := runArgon2id([]byte(password), []byte(username), 1, 64*1024, 8, 64)
        _, err := db.Exec("DELETE FROM " + CredentialTable + " WHERE hash=?", upperCredHash)
        if err != nil {
          failures = append(failures, failure{line, CredDeleteFailed, err})
        }
        // insert the lower case version
        lowerCredHash, _ := runArgon2id([]byte(password), []byte(strings.ToLower(username)), 1, 64*1024, 8, 64)
        _, err = db.Exec("INSERT INTO " + CredentialTable + " (hash) VALUES (?)", lowerCredHash)
        if err != nil {
          failures = append(failures, failure{line, CredInsertFailed, err})
        }
      }
    }
  }
  return failures, nil
}

func doEncryption(db *sql.DB, limit, offset int) {
  start := time.Now()
  totalEncryptionTime, numEncryptions, failures, err := encryptAndInsertAll(db, DataPath, limit, offset)
  if err != nil {
    log.Fatal(err)
  }
  // totalEncryptionTime, numEncryptions := readAllFiles("./data", 5)
  fmt.Println(numEncryptions, "credentials read, encrypted, and inserted in", time.Since(start))
  fmt.Println("Number of failures:", len(failures))
  avgDur, err := time.ParseDuration(strconv.FormatInt(totalEncryptionTime / int64(numEncryptions), 10) + "ns")
  if err != nil {
    log.Fatal(err)
  }
  fmt.Println("Average argon2id run time:", avgDur)
  writeFailures(failures, FailuresFilePath)
}

// set limit to -1 (or anything < 0) to read all lines
func encryptAndInsertAll(db *sql.DB, path string, limit, offset int) (int64, int, []failure, error) {
  start := time.Now()
  totalEncryptionTime := int64(0)
  numEncryptions := 0
  failures := []failure{}
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
    line := strings.TrimSpace(scanner.Text())
    username, password, err := parseCredential(line)
    if err != nil {
      failures = append(failures, failure{line, ParseFailed, err})
    } else {
      credHash, execTime := runArgon2id([]byte(password), []byte(strings.ToLower(username)), 1, 64*1024, 8, 64)
      totalEncryptionTime += execTime.Nanoseconds()
      numEncryptions += 1
      _, err := db.Exec("INSERT INTO " + CredentialTable + " (hash) VALUES (?)", credHash)
      if err != nil {
        // skip dupe errors
        matched, _ := regexp.MatchString(dupeRegexp, err.Error())
        if !matched {
          failures = append(failures, failure{line, CredInsertFailed, err})
        }
      }
      // fail, err := analyzePassword(db, password)
      // if err != nil {
      //   failures = append(failures, fail)
      // }
    }
    if numEncryptions > 0 && numEncryptions % 10000 == 0 {
      fmt.Println(numEncryptions, "credentials encrypted and inserted in", time.Since(start), "so far")
      avgDur, err := time.ParseDuration(strconv.FormatInt(totalEncryptionTime / int64(numEncryptions), 10) + "ns")
      if err == nil {
        fmt.Println("Average argon2id run time so far:", avgDur)
      }
    }
  }
  if err := scanner.Err(); err != nil {
    fmt.Printf("Invalid input: %s\n", err)
  }
  return totalEncryptionTime, numEncryptions, failures, nil
}

func parseCredential(cred string) (string, string, error) {
  tabMatched, _ := regexp.MatchString("^[^\\t]+\\t[^\\t]+$", cred)
  if tabMatched {
  	result := strings.Split(cred, "\t")
  	return result[0], result[1], nil
  }
 	spaceMatched, _ := regexp.MatchString("^[^\\s]+\\s[^\\s]+$", cred)
 	if spaceMatched {
 		result := strings.Split(cred, " ")
 		return result[0], result[1], nil
 	}
 	return "", "", errors.New("Unable to parse credential " + cred)
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

func writeFailures(failures []failure, path string) {
  if len(failures) > 0 {
    var file *os.File
    var err error
    file, err = os.OpenFile(path, os.O_APPEND, 0644)
    if err != nil {
      file, err = os.Create(path)
      if err != nil {
        log.Fatal(err)
      }
    }
    defer file.Close()
    w := bufio.NewWriter(file)
    for _, failure := range failures {
      _, err := w.WriteString(failure.desc + "\t" + failure.err.Error() + "\t" + failure.line + "\n")
      if err != nil {
        fmt.Println(err)
      }
    }
    w.Flush()
  }
}

func main() {
  db, err := server.GetDevDB()
  if err != nil {
    log.Fatal(err)
  }
  defer db.Close()
  checkDB(db)
  // cleanUpFailures(FailuresFilePath)
  doEncryption(db, 1000000, 12000000)
}
