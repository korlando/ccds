// increments the least significant portion
// of a version string and prints it
package main

import (
  "fmt"
  "log"
  "os"
  "strconv"
  "strings"
)

func main() {
  if len(os.Args) < 2 {
    log.Fatal("Expected a version string as the first arg.")
  }
  version := os.Args[1]
  parts := strings.Split(version, ".")
  newVersion := ""
  for i, num := range parts {
    if i == len(parts) - 1 {
      numInt, err := strconv.Atoi(num)
      if err != nil {
        log.Fatal(err)
      }
      newVersion += strconv.Itoa(numInt + 1)
    } else {
      newVersion += num + "."
    }
  }
  fmt.Print(newVersion)
}
