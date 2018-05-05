package main

import (
  "bufio"
  "encoding/json"
  "flag"
  "fmt"
  "io/ioutil"
  "log"
  "os"
  "strings"
  "time"
  "unsafe"

  "ccds"
)

const dataPath = "../../data/data.tsv"
const statsPath = "../../data/pw-stats.json"

// tracks the totals, whereas stat stores percentage
type statHelper struct{
  totPW int
  totUniquePW int
  up int
  low int
  let int
  num int
  sym int
  letNum int
  letSym int
  numSym int
  letNumSym int
  upOnly int
  lowOnly int
  letOnly int
  numOnly int
  symOnly int
  letNumOnly int
  letSymOnly int
  numSymOnly int
}

type stat struct{
  TotPW int `json:"totalPasswords"`
  TotUniquePW int `json:"totalUniquePasswords"`
  Up float64 `json:"hasUppercase"`
  Low float64 `json:"hasLowercase"`
  Let float64 `json:"hasLetters"`
  Num float64 `json:"hasNumbers"`
  Sym float64 `json:"hasSymbols"`
  LetNum float64 `json:"hasLettersAndNumbers"`
  LetSym float64 `json:"hasLettersAndSymbols"`
  NumSym float64 `json:"hasNumbersAndSymbols"`
  LetNumSym float64 `json:"hasLettersNumbersAndSymbols"`
  UpOnly float64 `json:"hasUppercaseOnly"`
  LowOnly float64 `json:"hasLowercaseOnly"`
  LetOnly float64 `json:"hasLettersOnly"`
  NumOnly float64 `json:"hasNumbersOnly"`
  SymOnly float64 `json:"hasSymbolsOnly"`
  LetNumOnly float64 `json:"hasLettersAndNumbersOnly"`
  LetSymOnly float64 `json:"hasLettersAndSymbolsOnly"`
  NumSymOnly float64 `json:"hasNumbersAndSymbolsOnly"`
}

func analysisThread(path string, limit, offset int, cacheLimit int, helperChan chan *statHelper, errChan chan error) {
  h, err := analyzeAll(path, limit, offset, cacheLimit)
  helperChan <- h
  if err != nil {
    errChan <- err
    return
  }
  errChan <- nil
}

// set limit to -1 (or anything < 0) to read all lines
func analyzeAll(path string, limit, offset int, cacheLimit int) (h *statHelper, err error) {
  file, err := os.Open(path)
  if err != nil {
    return
  }
  defer file.Close()
  scanner := bufio.NewScanner(file)
  lines := 0
  h = &statHelper{}
  m := make(map[string]*ccds.PWData)
  // track the set of passwords
  p := make(map[string]bool)
  mSize := int(unsafe.Sizeof(m))
  pSize := int(unsafe.Sizeof(p))
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
    d, ok := m[pw]
    if ok {
      d.Count += 1
    } else {
      data := ccds.AnalyzePW(pw)
      m[pw] = &data
      mSize += 8 + (8 * len(pw)) + (8 * int(unsafe.Sizeof(data)))
    }
    // reset cache to clear up some memory
    if mSize >= cacheLimit {
      for pw, d = range m {
        exists := p[pw]
        updateStats(h, d, exists)
        if !exists {
          // move passwords to a different set to track uniqueness
          p[pw] = true
          pSize += 8 + (8* len(pw)) + 64
        }
      }
      m = make(map[string]*ccds.PWData)
      mSize = int(unsafe.Sizeof(m))
    }
  }
  if err := scanner.Err(); err != nil {
    fmt.Printf("Invalid input: %s\n", err)
  }
  for pw, d := range m {
    exists := p[pw]
    updateStats(h, d, exists)
  }
  return
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
}

func updatePercentages(s *stat, h *statHelper) {
  s.TotPW = h.totPW
  s.TotUniquePW = h.totUniquePW
  tot := float64(h.totUniquePW)
  if tot == 0 {
    return
  }
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
}

func updateStats(h *statHelper, d *ccds.PWData, exists bool) {
  h.totPW += d.Count
  if exists {
    return
  }
  h.totUniquePW += 1
  let := d.Upper || d.Lower
  if d.Upper {
    h.up += 1
    if !d.Lower && !d.Numbers && !d.Symbols {
      h.upOnly += 1
    }
  }
  if d.Lower {
    h.low += 1
    if !d.Upper && !d.Numbers && !d.Symbols {
      h.lowOnly += 1
    }
  }
  if let {
    h.let += 1
    if !d.Numbers && !d.Symbols {
      h.letOnly += 1
    }
  }
  if d.Numbers {
    h.num += 1
    if !let && !d.Symbols {
      h.numOnly += 1
    }
  }
  if d.Symbols {
    h.sym += 1
    if !let && !d.Numbers {
      h.symOnly += 1
    }
  }
  if let && d.Numbers {
    h.letNum += 1
    if !d.Symbols {
      h.letNumOnly += 1
    }
  }
  if let && d.Symbols {
    h.letSym += 1
    if !d.Numbers {
      h.letSymOnly += 1
    }
  }
  if d.Numbers && d.Symbols {
    h.numSym += 1
    if !let {
      h.numSymOnly += 1
    }
  }
  if let && d.Numbers && d.Symbols {
    h.letNumSym += 1
  }
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
  flag.IntVar(&cacheLimit, "cache", 100000, "Limit on size in bytes of the hashmap cache of passwords.")
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
  }
  start := time.Now()
  helperChan := make(chan *statHelper)
  errChan := make(chan error)
  step := limit / threads
  cacheLimit = cacheLimit / threads
  remaining := limit - (step * threads)
  lastLine := 0
  // split up the work
  for i := 0; i < threads; i += 1 {
    extra := 0
    if i < remaining {
      extra = 1
    }
    numLines := step + extra
    go analysisThread(path, numLines, lastLine + offset, cacheLimit, helperChan, errChan)
    lastLine += numLines
  }
  s := &stat{}
  helper := &statHelper{}
  // wait for chan responses
  for i := 0; i < threads; i += 1 {
    h := <- helperChan
    err := <- errChan
    if err != nil {
      fmt.Println(err)
    }
    // merge statHelpers; this needs to happen
    // before updateStats() to avoid duplicates
    if threads == 1 {
      helper = h
      continue
    }
    mergeHelpers(helper, h)
  }
  updatePercentages(s, helper)
  err = writeStats(s, statsPath)
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println("Run time:", time.Since(start))
}
