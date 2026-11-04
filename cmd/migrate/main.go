package main

import (
	"context"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"os"
	"threatservice/config"
	"threatservice/migrations"
	"time"
)

func run() error {
	c, err := config.Load()
	if err != nil {
		return err
	}
	dsn, err := c.DSN()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	return migrations.Up(ctx, conn)
}
func main() {
	if err := run(); err != nil {
		slog.Error("migration failed", "error", err)
		os.Exit(1)
	}
	slog.Info("migrations applied")
}
