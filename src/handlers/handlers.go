package handlers

import (
  "database/sql"
  "encoding/json"
  "io"
  "net/http"
  "ccds/src/factory"
)

type SearchCredHashRequestBody struct {
  Hash string `json:"hash"`
}

type SearchCredHashResponse struct {
  Compromised bool `json:"compromised"`
}

type SearchCredHashErr struct {
  Err string `json:"err"`
}

func SearchCredHashHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  var s SearchCredHashRequestBody
  err := decodeBody(r.Body, &s)
  if err != nil {
    respondWithJSON(w, http.StatusBadRequest, SearchCredHashErr{"Incorrect request body format: use {\"hash\": [string]}"})
  } else {
    compromised, err := factory.SearchCredHash(db, []byte(s.Hash))
    if err != nil {
      respondWithJSON(w, http.StatusBadRequest, SearchCredHashErr{err.Error()})
    } else {
      respondWithJSON(w, http.StatusOK, SearchCredHashResponse{compromised})
    }
  }
}

func decodeBody(body io.ReadCloser, v interface{}) error {
  decoder := json.NewDecoder(body)
  return decoder.Decode(v)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
  res, _ := json.Marshal(payload)
  w.Header().Set("Content-Type", "application/json")
  w.WriteHeader(code)
  w.Write(res)
}
