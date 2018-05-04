package ccds

import (
  "bytes"
  "errors"
  "io"
  "os"
  "regexp"
  "strings"
)

type PWData struct{
  Count int
  Length int
  Lower bool
  Upper bool
  Numbers bool
  Symbols bool
}

func AnalyzePW(pw string) (d PWData) {
  d.Count = 1
  d.Length = len(pw)
  hasLower, _ := regexp.MatchString("[a-z]", pw)
  hasUpper, _ := regexp.MatchString("[A-Z]", pw)
  hasNumbers, _ := regexp.MatchString("[0-9]", pw)
  hasSymbols, _ := regexp.MatchString("[^a-zA-Z0-9]", pw)
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
  return
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
