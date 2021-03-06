package ccds

import (
  "bytes"
  "encoding/json"
  "errors"
  "io"
  "net/http"
  "os"
  "regexp"
  "time"
  "strings"

  "github.com/korlando/ccds/server"
)

const Fmt1 = "^[a-zA-Z]+[0-9]+$"
const Fmt2 = "^[0-9]+[a-zA-Z]+$"

var net = &http.Client{
  Timeout: time.Second * 7,
}

type PWData struct{
  Count   uint
  Length  uint16
  Lower   bool
  Upper   bool
  Numbers bool
  Symbols bool
  Fmt1    bool
  Fmt2    bool
}

func AnalyzePW(pw string) (d PWData) {
  d.Count = 1
  d.Length = uint16(len(pw))
  hasLower, _ := regexp.MatchString("[a-z]", pw)
  hasUpper, _ := regexp.MatchString("[A-Z]", pw)
  hasNumbers, _ := regexp.MatchString("[0-9]", pw)
  hasSymbols, _ := regexp.MatchString("[^a-zA-Z0-9]", pw)
  isFmt1, _ := regexp.MatchString(Fmt1, pw)
  isFmt2, _ := regexp.MatchString(Fmt2, pw)
  if hasLower {
    d.Lower = true
  }
  if hasUpper {
    d.Upper = true
  }
  if hasNumbers {
    d.Numbers = true
  }
  if hasSymbols {
    d.Symbols = true
  }
  if isFmt1 {
    d.Fmt1 = true
  }
  if isFmt2 {
    d.Fmt2 = true
  }
  return
}

func Compromised(u, pw string) (compromised bool, err error) {
  hash, _ := DefaultArgon2([]byte(pw), []byte(strings.ToLower(u)))
  reqBody := server.CredReqBody{string(hash),"utf8"}
  b, err := json.Marshal(reqBody)
  if err != nil {
    return
  }
  req, err := http.NewRequest("POST", "https://airk.ai/v1/cred", bytes.NewBuffer(b))
  if err != nil {
    return
  }
  req.Header.Set("Content-Type", "application/json")
  res, err := net.Do(req)
  if err != nil {
    return
  }
  var credRes server.CredRes
  err = server.DecodeBody(res.Body, &credRes)
  if err != nil {
    return
  }
  return credRes.Compromised, nil
}

// counts the number of lines in the file at path
func CountLines(path string) (lines int, err error) {
  info, err := os.Stat(path)
  if err != nil {
    return
  }
  if info.IsDir() {
    err = errors.New("File at " + path + " is a directory.")
    return
  }
  file, err := os.Open(path)
  if err != nil {
    return
  }
  // https://stackoverflow.com/questions/24562942/golang-how-do-i-determine-the-number-of-lines-in-a-file-efficiently
  buf := make([]byte, 32*1024)
  sep := []byte{'\n'}
  for {
    n, err := file.Read(buf)
    lines += bytes.Count(buf[:n], sep)
    switch {
    case err == io.EOF:
      return lines, nil
    case err != nil:
      return lines, err
    }
  }
}

func ParseCred(cred, sep string) (string, string, error) {
  matched, _ := regexp.MatchString("^[^" + sep + "]+" + sep + "[^" + sep + "]+$", cred)
  if matched {
    result := strings.Split(cred, sep)
    return result[0], result[1], nil
  }
  return "", "", errors.New("Unable to parse credential " + cred)
}

func ParseCredTab(cred string) (string, string, error) {
  return ParseCred(cred, "\t")
}
