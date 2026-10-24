package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/VAibhav1031/revoke_token-go/handler"
	"github.com/jackc/pgx/v5/pgxpool"
	// "github.com/joho/godotenv"
)

// we need to have simple register , login ,  logout ,  post HTTP endpoint , GET HTTP endpoint.

func muxHandler(pool *pgxpool.Pool) *http.ServeMux {
	authHandle := handler.AuthBlockInitiliazer()
	dbPoolHandle := handler.NewPooler(pool)

	h := handler.NewHandler(authHandle, dbPoolHandle)
	newMux := http.NewServeMux()
	newMux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"code":"OK","status_code":200,"message":"success"}`))
	})
	newMux.HandleFunc("POST /auth/register", dbPoolHandle.RegisterHandler)
	newMux.HandleFunc("POST /auth/login", h.LoginHandler)
	newMux.HandleFunc("/auth/logout", handler.LogoutHandler)

	return newMux
}

func main() {
	//
	// err := godotenv.Load(".env")
	// if err != nil {
	// 	log.Printf(".env load error :%v", err)
	// }

	dbUrl := os.Getenv("DATABASE_URL")

	pool := handler.DBConnect(dbUrl)
	err := pool.Ping(context.Background())
	if err != nil {
		log.Fatalf("Unable to connect to the DB.. : %v", err)
	}

	mux := muxHandler(pool)
	fmt.Println("Hello revoke token")
	server := http.Server{
		Addr:           ":2102",
		Handler:        mux,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   15 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	server.ListenAndServe()
}
