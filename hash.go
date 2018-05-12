package ccds

import (
  "time"

  "golang.org/x/crypto/argon2"
)

func Argon2id(password, salt []byte, iterations, memory uint32, threads uint8, keyLen uint32) (key []byte, execTime time.Duration) {
  start := time.Now()
  // https://github.com/golang/crypto/blob/master/argon2/argon2.go
  key = argon2.IDKey(password, salt, iterations, memory, threads, keyLen)
  execTime = time.Since(start)
  return
}

func DefaultArgon2(password, salt []byte) ([]byte, time.Duration) {
  return Argon2id(password, salt, 1, 64*1024, 8, 64)
}
