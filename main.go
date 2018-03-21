package main

import (
  "encoding/hex"
  "fmt"
  "golang.org/x/crypto/argon2"
  "time"
)

func getArgon2idExecTime(password, salt []byte, iterations, memory uint32, threads uint8, keyLen uint32) (time.Duration, string) {
  start := time.Now()
  key := argon2.IDKey(password, salt, iterations, memory, threads, keyLen)
  keyHex := hex.EncodeToString(key)
  execTime := time.Since(start)
  return execTime, keyHex
}

func main() {
  execTime, key := getArgon2idExecTime([]byte("password"), []byte("abc123"), 1, 32*1024, 2, 256)
  fmt.Println(execTime)
  fmt.Println(key)
}
