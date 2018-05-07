package main

import (
  "bufio"
  "encoding/json"
  "flag"
  "fmt"
  "io/ioutil"
  "log"
  "os"
  "runtime"
  "strings"
  "time"

  _ "github.com/go-sql-driver/mysql"
  "ccds"
  "ccds/server"
)

const (
  dataPath = "../../data/data.tsv"
  statsPath = "../../data/pw-stats.json"
  pwDataTable = "pw_data_helper"
)

// tracks the totals, whereas stat stores percentage
type statHelper struct{
  totPW       uint
  totUniquePW uint
  up          uint
  low         uint
  let         uint
  num         uint
  sym         uint
  letNum      uint
  letSym      uint
  numSym      uint
  letNumSym   uint
  upOnly      uint
  lowOnly     uint
  letOnly     uint
  numOnly     uint
  symOnly     uint
  letNumOnly  uint
  letSymOnly  uint
  numSymOnly  uint
  fmt1        uint
  fmt2        uint
  lengths     *map[uint16]uint // key: pw length, value: num pws
}

type stat struct{
  TotPW       uint            `json:"totalPasswords"`
  TotUniquePW uint            `json:"totalUniquePasswords"`
  Unique      float64         `json:"uniquePasswordsPercent"`
  Up          float64         `json:"hasUppercase"`
  Low         float64         `json:"hasLowercase"`
  Let         float64         `json:"hasLetters"`
  Num         float64         `json:"hasNumbers"`
  Sym         float64         `json:"hasSymbols"`
  LetNum      float64         `json:"hasLettersAndNumbers"`
  LetSym      float64         `json:"hasLettersAndSymbols"`
  NumSym      float64         `json:"hasNumbersAndSymbols"`
  LetNumSym   float64         `json:"hasLettersNumbersAndSymbols"`
  UpOnly      float64         `json:"hasUppercaseOnly"`
  LowOnly     float64         `json:"hasLowercaseOnly"`
  LetOnly     float64         `json:"hasLettersOnly"`
  NumOnly     float64         `json:"hasNumbersOnly"`
  SymOnly     float64         `json:"hasSymbolsOnly"`
  LetNumOnly  float64         `json:"hasLettersAndNumbersOnly"`
  LetSymOnly  float64         `json:"hasLettersAndSymbolsOnly"`
  NumSymOnly  float64         `json:"hasNumbersAndSymbolsOnly"`
  Fmt1        float64         `json:"format^[a-zA-Z]+[0-9]+$"`
  Fmt2        float64         `json:"format^[0-9]+[a-zA-Z]+$"`
  Lengths     map[uint16]uint `json:"passwordLengths"`
}

func analysisThread(path string, limit, offset int, cacheLimit int, dbMode *bool, helperChan chan *statHelper, cacheChan chan *map[string]*ccds.PWData, errChan chan error) {
  h, cache, err := analyzeAll(path, limit, offset, cacheLimit, dbMode)
  helperChan <- &h
  cacheChan <- &cache
  if err != nil {
    errChan <- err
    return
  }
  errChan <- nil
}

// set limit to -1 (or anything < 0) to read all lines
// set cacheLimit to -1 to remove memory bound on cache
func analyzeAll(path string, limit, offset int, cacheLimit int, dbMode *bool) (h statHelper, cache map[string]*ccds.PWData, err error) {
  db, err := server.GetDevDB()
  if err != nil {
    return
  }
  defer db.Close()
  err = db.Ping()
  if err != nil {
    return
  }
  file, err := os.Open(path)
  if err != nil {
    return
  }
  defer file.Close()
  scanner := bufio.NewScanner(file)
  lines := 0
  h = statHelper{}
  lengths := make(map[uint16]uint)
  h.lengths = &lengths
  cache = make(map[string]*ccds.PWData)
  for (limit < 0 || lines < limit + offset) && scanner.Scan() {
    lines += 1
    if lines <= offset {
      continue
    }
    line := strings.TrimSpace(scanner.Text())
    _, pw, err := ccds.ParseCredTab(line)
    if err != nil {
      continue
    }
    h.totPW += 1
    data, ok := cache[pw]
    if ok {
      data.Count += 1
    } else {
      d := ccds.AnalyzePW(pw)
      if !*dbMode {
        cache[pw] = &d
      } else {
        // cache too big, use db to check uniqueness
        var exists bool
        err = db.QueryRow("SELECT EXISTS(SELECT * FROM " + pwDataTable + " WHERE pw = BINARY ? LIMIT 1)", pw).Scan(&exists)
        if !exists {
          _, err = db.Exec("INSERT INTO " + pwDataTable + " (pw) VALUES (?)", pw)
          if err == nil {
            updateStats(&h, &d, false)
          }
        } else {
          updateStats(&h, &d, true)
        }
      }
    }
  }
  if err := scanner.Err(); err != nil {
    fmt.Printf("Invalid input: %s\n", err)
  }
  return
}

// logic for incrementing stats by "a" amount
func incrementHelper(h *statHelper, d *ccds.PWData, a uint) {
  h.totUniquePW += a
  let := d.Upper || d.Lower
  if d.Upper {
    h.up += a
    if !d.Lower && !d.Numbers && !d.Symbols {
      h.upOnly += a
    }
  }
  if d.Lower {
    h.low += a
    if !d.Upper && !d.Numbers && !d.Symbols {
      h.lowOnly += a
    }
  }
  if let {
    h.let += a
    if !d.Numbers && !d.Symbols {
      h.letOnly += a
    }
  }
  if d.Numbers {
    h.num += a
    if !let && !d.Symbols {
      h.numOnly += a
    }
  }
  if d.Symbols {
    h.sym += a
    if !let && !d.Numbers {
      h.symOnly += a
    }
  }
  if let && d.Numbers {
    h.letNum += a
    if !d.Symbols {
      h.letNumOnly += a
    }
  }
  if let && d.Symbols {
    h.letSym += a
    if !d.Numbers {
      h.letSymOnly += a
    }
  }
  if d.Numbers && d.Symbols {
    h.numSym += a
    if !let {
      h.numSymOnly += a
    }
  }
  if let && d.Numbers && d.Symbols {
    h.letNumSym += a
  }
  if d.Fmt1 {
    h.fmt1 += a
  }
  if d.Fmt2 {
    h.fmt2 += a
  }
  _, ok := (*h.lengths)[d.Length]
  if ok {
    (*h.lengths)[d.Length] += a
  } else {
    (*h.lengths)[d.Length] = a
  }
}

// merges h2's stats into h1
func mergeHelpers(h1, h2 *statHelper) {
  h1.totPW += h2.totPW
  h1.totUniquePW += h2.totUniquePW
  h1.up += h2.up
  h1.low += h2.low
  h1.let += h2.let
  h1.num += h2.num
  h1.sym += h2.sym
  h1.letNum += h2.letNum
  h1.letSym += h2.letSym
  h1.numSym += h2.numSym
  h1.letNumSym += h2.letNumSym
  h1.upOnly += h2.upOnly
  h1.lowOnly += h2.lowOnly
  h1.letOnly += h2.letOnly
  h1.numOnly += h2.numOnly
  h1.symOnly += h2.symOnly
  h1.letNumOnly += h2.letNumOnly
  h1.letSymOnly += h2.letSymOnly
  h1.numSymOnly += h2.numSymOnly
  h1.fmt1 += h2.fmt1
  h1.fmt2 += h2.fmt2
  for pwLen := range *h1.lengths {
    count, ok := (*h2.lengths)[pwLen]
    if ok {
      (*h1.lengths)[pwLen] += count
    }
  }
  for pwLen, count := range *h2.lengths {
    _, ok := (*h1.lengths)[pwLen]
    if !ok {
      (*h1.lengths)[pwLen] = count
    }
  }
}

// h1 and cacheList are main
// h2 and c come from the thread
func mergeThreadResults(h1, h2 *statHelper, cacheList *[]*map[string]*ccds.PWData, c *map[string]*ccds.PWData) (collisions int) {
  mergeHelpers(h1, h2)
  collisions = 0
  for pw, d := range *c {
    var exists bool
    for _, cPtr := range *cacheList {
      if cPtr == nil {
        continue
      }
      _, hit := (*cPtr)[pw]
      if hit {
        exists = true
        break
      }
    }
    updateStats(h1, d, exists)
    if exists {
      collisions += 1
    }
  }
  return
}

func updateDbMode(dbMode *bool, cacheLimit int, pollRate time.Duration) {
  for !*dbMode {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    fmt.Println("Memory imprint:", m.Alloc / 1000000, "MB")
    if m.Alloc >= uint64(cacheLimit) {
      *dbMode = true
      fmt.Println("Switching to DB mode...")
    } else {
      time.Sleep(pollRate)
    }
  }
}

func updatePercentages(s *stat, h *statHelper) {
  s.TotPW = h.totPW
  s.TotUniquePW = h.totUniquePW
  tot := float64(h.totUniquePW)
  if tot == 0 {
    return
  }
  s.Unique = tot / float64(h.totPW)
  s.Up = float64(h.up) / tot
  s.Low = float64(h.low) / tot
  s.Let = float64(h.let) / tot
  s.Num = float64(h.num) / tot
  s.Sym = float64(h.sym) / tot
  s.LetNum = float64(h.letNum) / tot
  s.LetSym = float64(h.letSym) / tot
  s.NumSym = float64(h.numSym) / tot
  s.LetNumSym = float64(h.letNumSym) / tot
  s.UpOnly = float64(h.upOnly) / tot
  s.LowOnly = float64(h.lowOnly) / tot
  s.LetOnly = float64(h.letOnly) / tot
  s.NumOnly = float64(h.numOnly) / tot
  s.SymOnly = float64(h.symOnly) / tot
  s.LetNumOnly = float64(h.letNumOnly) / tot
  s.LetSymOnly = float64(h.letSymOnly) / tot
  s.NumSymOnly = float64(h.numSymOnly) / tot
  s.Fmt1 = float64(h.fmt1) / tot
  s.Fmt2 = float64(h.fmt2) / tot
  s.Lengths = *h.lengths
}

func updateStats(h *statHelper, d *ccds.PWData, exists bool) {
  if exists {
    return
  }
  incrementHelper(h, d, 1)
}

func writeStats(s *stat, path string) (err error) {
  jsonBytes, err := json.Marshal(s)
  if err != nil {
    return
  }
  err = ioutil.WriteFile(path, jsonBytes, 0644)
  return
}

func main() {
  var path string
  var limit int
  var offset int
  var threads int
  var cacheLimit int
  flag.StringVar(&path, "path", dataPath, "Path to the data file.")
  flag.IntVar(&limit, "limit", 0, "Limit on the number of credentials to read.")
  flag.IntVar(&offset, "offset", 0, "Offset the line to start reading from (0-indexed).")
  flag.IntVar(&threads, "threads", 1, "Number of threads to parallelize reading of the file.")
  flag.IntVar(&cacheLimit, "cache", 100000, "Limit on size in bytes of the hashmap cache of passwords. Set to -1 to remove limit.")
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
  if limit < 0 {
    fmt.Println("Calculating number of credentials...")
    lines, err := ccds.CountLines(path)
    if err != nil {
      log.Fatal(err)
    }
    limit = lines
    fmt.Println("Analyzing", lines, "lines...")
  }
  start := time.Now()
  dbMode := cacheLimit == 0
  helperChan := make(chan *statHelper)
  cacheChan := make(chan *map[string]*ccds.PWData)
  errChan := make(chan error)
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
    go analysisThread(path, numLines, lastLine + offset, cacheLimit, &dbMode, helperChan, cacheChan, errChan)
    lastLine += numLines
  }
  if !dbMode && cacheLimit >= 0 {
    go updateDbMode(&dbMode, cacheLimit, 5 * time.Second)
  }
  s := &stat{}
  helper := &statHelper{}
  lengths := make(map[uint16]uint)
  helper.lengths = &lengths
  cacheList := make([]*map[string]*ccds.PWData, threads)
  collisions := 0
  // wait for chan responses
  for i := 0; i < threads; i += 1 {
    h := <- helperChan
    c := <- cacheChan
    err := <- errChan
    if err != nil {
      fmt.Println(err)
    }
    if threads == 1 {
      helper = h
      for _, d := range *c {
        updateStats(helper, d, false)
      }
      continue
    }
    collisions += mergeThreadResults(helper, h, &cacheList, c)
    cacheList[i] = c
  }
  updatePercentages(s, helper)
  err = writeStats(s, statsPath)
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println("Run time:", time.Since(start))
  if threads > 1 {
    fmt.Println("Password collisions between threads:", collisions)
  }
  var m runtime.MemStats
  runtime.ReadMemStats(&m)
  fmt.Println("Total memory usage:", m.TotalAlloc, "bytes")
}
