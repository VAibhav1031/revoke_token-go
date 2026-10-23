package handler

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func DBConnect(urlString string) *pgxpool.Pool {
	config, err := pgxpool.ParseConfig(urlString)
	if err != nil {
		log.Printf("DB connection Error: %v", err)
		return nil
	}

	config.MaxConns = 50
	config.MinConns = 20
	config.MinIdleConns = 5
	config.MaxConnIdleTime = 15 * time.Second
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		log.Printf("Unable To create the Connection Pool: %v", err)
		return nil
	}

	return pool
}
