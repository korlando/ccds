package ccds

import (
  "bytes"
  "errors"
  "io"
  "os"
  "regexp"
  "strings"
)

// Lower, Upper, Numbers, and Symbols are
// int representations of booleans (0 or 1)
type PWData struct{
  Count int
  Length int
  Lower int
  Upper int
  Numbers int
  Symbols int
}

func AnalyzePW(pw string) PWData {
  length := len(pw)
  hasLower, _ := regexp.MatchString("[a-z]", pw)
  hasUpper, _ := regexp.MatchString("[A-Z]", pw)
  hasNumbers, _ := regexp.MatchString("[0-9]", pw)
  hasSymbols, _ := regexp.MatchString("[^a-zA-Z0-9]", pw)
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
  return PWData{1, length, low, up, num, sym}
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
