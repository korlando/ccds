package server

import (
	"database/sql"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

type App struct {
	RouterV1 *mux.Router
	DB       *sql.DB
}

func (a *App) Initialize(db *sql.DB) {
	a.DB = db
	r := mux.NewRouter()
	s := r.
		PathPrefix("/v1").
		Schemes("https").
		Subrouter()
	a.RouterV1 = s
	a.initializeRoutes()
}

func (a *App) Run(addr string) {
	log.Fatal(http.ListenAndServe(addr, a.RouterV1))
}

func (a *App) initializeRoutes() {
	a.RouterV1.HandleFunc("/credhash", a.searchCredHashHandler).Methods("POST")
}

func (a *App) searchCredHashHandler(w http.ResponseWriter, r *http.Request) {
	SearchCredHashHandler(w, r, a.DB)
}
