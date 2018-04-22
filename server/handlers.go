package server

import (
  "bytes"
  "database/sql"
  "encoding/json"
  "io"
  "net/http"
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
  l := r.ContentLength
  if l == -1 {
    l = 64
  }
  b := bytes.NewBuffer(make([]byte, 0, l))
  _, err := b.ReadFrom(r.Body)
  if err != nil {
    respondWithJSON(w, http.StatusBadRequest, SearchCredHashErr{"An error occurred while reading the hash bytes"})
    return
  }
  compromised, err := SearchCredHash(db, b.Bytes())
  if err != nil {
    respondWithJSON(w, http.StatusBadRequest, SearchCredHashErr{err.Error()})
  } else {
    respondWithJSON(w, http.StatusOK, SearchCredHashResponse{compromised})
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
