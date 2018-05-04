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

  "ccds"
)

const dataPath = "../../data/data.tsv"
const statsPath = "../../data/pw-stats.json"

// tracks the totals, whereas stat stores percentage
type statHelper struct{
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

func analysisThread(path string, limit, offset int, mapChan chan *map[string]*ccds.PWData, errChan chan error) {
  m, err := analyzeAll(path, limit, offset)
  mapChan <- &m
  if err != nil {
    errChan <- err
    return
  }
  errChan <- nil
}

// set limit to -1 (or anything < 0) to read all lines
func analyzeAll(path string, limit, offset int) (m map[string]*ccds.PWData, err error) {
  file, err := os.Open(path)
  if err != nil {
    return
  }
  defer file.Close()
  scanner := bufio.NewScanner(file)
  lines := 0
  m = make(map[string]*ccds.PWData)
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
    }
  }
  if err := scanner.Err(); err != nil {
    fmt.Printf("Invalid input: %s\n", err)
  }
  fmt.Println("")
  return
}

func updatePercentages(s *stat, h *statHelper) {
  tot := float64(s.TotUniquePW)
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
  s.LetNumOnly = float64(h.letNumOnly) / tot
  s.LetSymOnly = float64(h.letSymOnly) / tot
  s.NumSymOnly = float64(h.numSymOnly) / tot
}

func updateStats(s *stat, h *statHelper, d *ccds.PWData) {
  s.TotPW += d.Count
  s.TotUniquePW += 1
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
  flag.StringVar(&path, "path", dataPath, "Path to the data file.")
  flag.IntVar(&limit, "limit", 0, "Limit on the number of credentials to read.")
  flag.IntVar(&offset, "offset", 0, "Offset the line to start reading from (0-indexed).")
  flag.IntVar(&threads, "threads", 1, "Number of threads to parallelize reading of the file.")
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
  errChan := make(chan error)
  mapChan := make(chan *map[string]*ccds.PWData)
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
    go analysisThread(path, numLines, lastLine + offset, mapChan, errChan)
    lastLine += numLines
  }
  pwMap := make(map[string]*ccds.PWData)
  s := &stat{}
  h := &statHelper{}
  // wait for chan responses
  for i := 0; i < threads; i += 1 {
    m := <- mapChan
    err := <- errChan
    if err != nil {
      fmt.Println(err)
    }
    // merge into one map; this needs to happen
    // before updateStats() to avoid duplicates
    if threads == 1 {
      pwMap = *m
      continue
    }
    for pw, d := range *m {
      existing, ok := pwMap[pw]
      if ok {
        existing.Count += d.Count
      } else {
        pwMap[pw] = d
      }
    }
  }
  for _, d := range pwMap {
    updateStats(s, h, d)
  }
  updatePercentages(s, h)
  err = writeStats(s, statsPath)
  if err != nil {
    fmt.Println(err)
  }
  fmt.Println("Run time:", time.Since(start))
}
