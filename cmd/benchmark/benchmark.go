package main

import (
  "flag"
  "fmt"
  "log"
  "math/rand"
  "strconv"
  "strings"
  "time"

  "golang.org/x/crypto/argon2"
)

const characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789~!@#$%^&*()_+-=`{}[]:;<>.,?|\\/\"'"

type credential struct {
  username string
  password string
}

func encryptionThread(steps int, doneChan chan bool) {
  start := time.Now()
  totalEncryptionTime := int64(0)
  // generate some credentials
  credentials := make([]credential, steps, steps)
  for i := 0; i < steps; i += 1 {
    credentials[i] = credential{randStr(16), randStr(16)}
  }
  for _, cred := range credentials {
    execTime := timeArgon2id([]byte(cred.password), []byte(strings.ToLower(cred.username)), 1, 64*1024, 8, 64)
    totalEncryptionTime += execTime.Nanoseconds()
  }
  fmt.Println(steps, "credentials encrypted in", time.Since(start))
  printAvgDur(totalEncryptionTime, steps)
  doneChan <- true
}

func getThroughput(total int64, num int) float64 {
  return (float64(num) * 1000000000) / float64(total)
}

func printAvgDur(total int64, num int) {
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
    avgSpeed = strconv.FormatFloat(getThroughput(total, num), 'f', 5, 64)
  }
  fmt.Println("Avg argon2id run time:", avgDur, "(" + avgSpeed + " hashes/sec)")
}

func randStr(length int) string {
  strBytes := make([]byte, length, length)
  for i := 0; i < length; i += 1 {
    strBytes[i] = characters[rand.Intn(len(characters))]
  }
  return string(strBytes)
}

func timeArgon2id(password, salt []byte, iterations, memory uint32, threads uint8, keyLen uint32) time.Duration {
  start := time.Now()
  _ = argon2.IDKey(password, salt, iterations, memory, threads, keyLen)
  return time.Since(start)
}

func main() {
  var number int
  var threads int
  flag.IntVar(&number, "n", 1000, "Number of credentials to generate and encrypt.")
  flag.IntVar(&threads, "t", 1, "Number of threads to parallelize reading and encryption of the file (not parallelism to use in argon2id).")
  flag.Parse()
  if threads <= 0 {
    log.Fatal("Threads should be at least 1.")
  }
  threadSuffix := "s"
  if threads == 1 {
    threadSuffix = ""
  }
  fmt.Println("Benchmarking with", threads, "thread" + threadSuffix + "...")
  start := time.Now()
  doneChan := make(chan bool)
  step := number / threads
  remaining := number - (step * threads)
  // split up the work
  for i := 0; i < threads; i += 1 {
    extra := 0
    if i < remaining {
      extra = 1
    }
    numSteps := step + extra
    go encryptionThread(numSteps, doneChan)
  }
  // wait for chan responses
  for i := 0; i < threads; i += 1 {
    <-doneChan
  }
  fmt.Println()
  fmt.Println("Total throughput:", getThroughput(time.Since(start).Nanoseconds(), number), "hashes/sec")
  fmt.Println("Run time:", time.Since(start))
}
