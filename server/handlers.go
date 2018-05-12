package server

import (
  "database/sql"
  "encoding/json"
  "io"
  "net/http"
)

type CredReqBody struct{
  Hash     string `json:"hash"`
  Encoding string `json:"encoding"`
}

type CredRes struct{
  Compromised bool `json:"compromised"`
}

type credErr struct{
  Err string `json:"err"`
}

func CredHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  var req CredReqBody
  err := DecodeBody(r.Body, &req)
  if err != nil {
    respondWithJSON(w, http.StatusBadRequest, credErr{"An error occurred parsing the request body"})
    return
  }
  var hash []byte
  switch req.Encoding {
  case "utf8":
    hash = []byte(req.Hash)
  default:
    hash = []byte(req.Hash)
  }
  compromised, err := SearchCredHash(db, hash)
  if err != nil {
    respondWithJSON(w, http.StatusBadRequest, credErr{err.Error()})
  } else {
    respondWithJSON(w, http.StatusOK, CredRes{compromised})
  }
}

func DecodeBody(body io.ReadCloser, v interface{}) error {
  decoder := json.NewDecoder(body)
  return decoder.Decode(v)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
  res, _ := json.Marshal(payload)
  w.Header().Set("Content-Type", "application/json")
  w.WriteHeader(code)
  w.Write(res)
}
