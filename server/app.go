package server

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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
		Subrouter()
	a.RouterV1 = s
	a.initializeRoutes()
}

func (a *App) Run(addr string) {
	// https://github.com/gorilla/mux#graceful-shutdown
	srv := &http.Server{
		Addr:    addr,
		Handler: a.RouterV1,
	}
	log.Println("Starting CCDS server on", addr, "...")
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			log.Println(err)
		}
	}()
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c
	wait, _ := time.ParseDuration("15s")
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	log.Println("Shutting down CCDS server...")
	srv.Shutdown(ctx)
	os.Exit(0)
}

func (a *App) initializeRoutes() {
	a.RouterV1.HandleFunc("/cred", a.credHandler).Methods("POST")
}

func (a *App) credHandler(w http.ResponseWriter, r *http.Request) {
	CredHandler(w, r, a.DB)
}
