package main

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"threatservice/config"
	"threatservice/infra/postgres"
	"threatservice/internal/threat"
	transport "threatservice/transport/http"
	"time"
)

func run() error {
	c, err := config.Load()
	if err != nil {
		return err
	}
	key, err := config.ReadSecret(c.APIKeyFile)
	if err != nil {
		return err
	}
	dsn, err := c.DSN()
	if err != nil {
		return err
	}
	pc, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return err
	}
	pc.MaxConns = c.Postgres.MaxConns
	pc.MinConns = 1
	pc.MaxConnLifetime = 30 * time.Minute
	pc.MaxConnIdleTime = 5 * time.Minute
	startup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(startup, pc)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err = pool.Ping(startup); err != nil {
		return err
	}
	e, err := transport.New(threat.New(postgres.New(pool)), key, c.HTTP.RequestTimeout, pool.Ping)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: c.HTTP.Address, Handler: e, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	slog.Info("server starting", "address", c.HTTP.Address)
	select {
	case err := <-result:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}
	shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	return server.Shutdown(shutdown)
}
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
