package server

import (
  "database/sql"
  "encoding/json"
  "io"
  "net/http"
)

type credReqBody struct{
  hash     string
  encoding string
}

type credRes struct{
  Compromised bool `json:"compromised"`
}

type credErr struct{
  Err string `json:"err"`
}

func CredHandler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
  var req credReqBody
  err := decodeBody(r.Body, &req)
  if err != nil {
    respondWithJSON(w, http.StatusBadRequest, credErr{"An error occurred parsing the request body"})
    return
  }
  var hash []byte
  switch req.encoding {
  case "utf8":
    hash = []byte(req.hash)
  default:
    hash = []byte(req.hash)
  }
  compromised, err := SearchCredHash(db, hash)
  if err != nil {
    respondWithJSON(w, http.StatusBadRequest, credErr{err.Error()})
  } else {
    respondWithJSON(w, http.StatusOK, credRes{compromised})
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
