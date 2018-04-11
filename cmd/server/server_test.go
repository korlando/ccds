package main_test

import (
  "net/http"
  "net/http/httptest"
  "log"
  "os"
  "testing"
  "ccds/server"
)

const credhashTableCreationQuery = `
  CREATE TABLE IF NOT EXISTS cred_hash_1_64_8_64 (
    hash varbinary(64) NOT NULL,
    checked int(11) DEFAULT '0',
    PRIMARY KEY (hash),
    UNIQUE KEY hash_UNIQUE (hash)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
`

var a main.App

func TestMain(m *testing.M) {
  a = main.App{}
  a.Initialize(
    os.Getenv("CCDS_DB_USER"),
    os.Getenv("CCDS_DB_PW"),
    os.Getenv("CCDS_DB_NAME"),
  )
  ensureTableExists()
  code := m.Run()
  os.Exit(code)
}

func TestSearch(t *testing.T) {
  req, _ := http.NewRequest("GET", "/credhash", nil)
  response := executeRequest(req)
  checkResponseCode(t, http.StatusOK, response.Code)
}

func checkResponseCode(t *testing.T, expected, actual int) {
  if expected != actual {
    t.Errorf("Expected response code %d. Got %d\n", expected, actual)
  }
}

func ensureTableExists() {
  if _, err := a.DB.Exec(credhashTableCreationQuery); err != nil {
    log.Fatal(err)
  }
}

func executeRequest(req *http.Request) *httptest.ResponseRecorder {
  rr := httptest.NewRecorder()
  a.Router.ServeHTTP(rr, req)
  return rr
}
