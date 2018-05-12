package main

import (
  "bufio"
  "database/sql"
  "flag"
  "fmt"
  "log"
  "os"
  "regexp"
  "strconv"
  "strings"
  "time"

  "golang.org/x/crypto/argon2"
  _ "github.com/go-sql-driver/mysql"
  "github.com/korlando/ccds"
  "github.com/korlando/ccds/server"
)

const ParseFailed = "Parse"
const CredInsertFailed = "CredInsert"
const IncrementFailed = "Increment"

const dataPath = "../../data/data.tsv"
const failuresPath = "../../data/failures.txt"

const dupeRegexp = "^Error 1062: Duplicate entry.+$"

type failure struct {
  line string
  desc string
  err error
}

// set limit to -1 (or anything < 0) to read all lines
func encryptAndInsertAll(db *sql.DB, path string, limit, offset int) (encryptTime int64, encryptNum int, failures []failure, err error) {
  start := time.Now()
  file, err := os.Open(path)
  if err != nil {
    return
  }
  defer file.Close()
  scanner := bufio.NewScanner(file)
  lines := 0
  for (limit < 0 || lines < limit + offset) && scanner.Scan() {
    lines += 1
    if lines <= offset {
      continue
    }
    line := strings.TrimSpace(scanner.Text())
    username, password, err := ccds.ParseCredTab(line)
    if err != nil {
      failures = append(failures, failure{line, ParseFailed, err})
      continue
    }
    credHash, execTime := ccds.DefaultArgon2([]byte(password), []byte(strings.ToLower(username)))
    encryptTime += execTime.Nanoseconds()
    encryptNum += 1
    _, err = db.Exec("INSERT INTO " + server.CredHashTable + " (hash) VALUES (?)", credHash)
    if err != nil {
      // skip dupe errors
      matched, _ := regexp.MatchString(dupeRegexp, err.Error())
      if !matched {
        failures = append(failures, failure{line, CredInsertFailed, err})
      }
    }
    if encryptNum > 0 && encryptNum % 10000 == 0 {
      fmt.Println(encryptNum, "credentials encrypted in", time.Since(start), "so far")
      printAvgDur(encryptTime, encryptNum, "Avg argon2id run time so far:")
    }
  }
  if err := scanner.Err(); err != nil {
    fmt.Printf("Invalid input: %s\n", err)
  }
  return
}

func encryptionThread(db *sql.DB, path string, limit, offset int, errChan chan error, failureChan chan []failure) {
  start := time.Now()
  encryptTime, encryptNum, failures, err := encryptAndInsertAll(db, path, limit, offset)
  if err != nil {
    errChan <- err
    failureChan <- failures
    return
  }
  fmt.Println(encryptNum, "credentials encrypted in", time.Since(start))
  printAvgDur(encryptTime, encryptNum, "")
  errChan <- nil
  failureChan <- failures
}

func printAvgDur(total int64, num int, desc string) {
  if desc == "" {
    desc = "Avg argon2id run time:"
  }
  avgDur, _ := time.ParseDuration("0ms")
  avgSpeed := "0"
  if num != 0 {
    avg, err := time.ParseDuration(strconv.FormatInt(total / int64(num), 10) + "ns")
    if err != nil {
      return
    }
    avgDur = avg
  }
  if total != 0 {
    avgSpeed = strconv.FormatFloat((float64(num) * 1000000000) / float64(total), 'f', 5, 64)
  }
  fmt.Println(desc, avgDur, "(" + avgSpeed + " hashes/sec)")
}

func writeFailures(failures []failure, path string) {
  if len(failures) == 0 {
    return
  }
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

func main() {
  db, err := server.GetDevDB()
  if err != nil {
    log.Fatal(err)
  }
  defer db.Close()
  err = db.Ping()
  if err != nil {
    log.Fatal(err)
  }
  var path string
  var limit int
  var offset int
  var threads int
  flag.StringVar(&path, "path", dataPath, "Path to the data file.")
  flag.IntVar(&limit, "limit", 0, "Limit on the number of credentials to read.")
  flag.IntVar(&offset, "offset", 0, "Offset the line to start reading from (0-indexed).")
  flag.IntVar(&threads, "threads", 1, "Number of threads to parallelize reading of the file (not parallelism to use in argon2id).")
  flag.Parse()
  info, err := os.Stat(path)
  if err != nil && os.IsNotExist(err) {
    log.Fatal("File at " + path + " does not exist.")
  }
  if info.IsDir() {
    log.Fatal("File at " + path + " is a directory.")
  }
  if threads <= 0 {
    log.Fatal("Threads should be at least 1.")
  }
  limit = 700000
  offset = 31300000
  if limit < 0 {
    fmt.Println("Calculating number of credentials...")
    lines, err := ccds.CountLines(path)
    if err != nil {
      log.Fatal(err)
    }
    limit = lines
  }
  start := time.Now()
  errChan := make(chan error)
  failureChan := make(chan []failure)
  step := limit / threads
  remaining := limit - (step * threads)
  lastLine := 0
  // split up the work
  for i := 0; i < threads; i += 1 {
    extra := 0
    if i < remaining {
      extra = 1
    }
    numLines := step + extra
    go encryptionThread(db, path, numLines, lastLine + offset, errChan, failureChan)
    lastLine += numLines
  }
  allFailures := []failure{}
  // wait for chan responses
  for i := 0; i < threads; i += 1 {
    err := <- errChan
    failures := <- failureChan
    if err != nil {
      fmt.Println(err)
    }
    allFailures = append(allFailures, failures...)
  }
  writeFailures(allFailures, failuresPath)
  fmt.Println("Run time:", time.Since(start))
  fmt.Println("Number of failures:", len(allFailures))
}
