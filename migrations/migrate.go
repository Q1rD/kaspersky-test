// Package migrations applies embedded, checksum-verified SQL under a transaction lock.
package migrations

import (
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"github.com/jackc/pgx/v5"
)

//go:embed *.sql
var files embed.FS

func Up(ctx context.Context, conn *pgx.Conn) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(74001001)`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, sha256 TEXT NOT NULL, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	entries, err := files.ReadDir(".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		sql, err := files.ReadFile(entry.Name())
		if err != nil {
			return err
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(sql))
		var previous string
		err = tx.QueryRow(ctx, `SELECT sha256 FROM schema_migrations WHERE name=$1`, entry.Name()).Scan(&previous)
		if err == nil {
			if previous != digest {
				return fmt.Errorf("migration checksum changed: %s", entry.Name())
			}
			continue
		}
		if err != pgx.ErrNoRows {
			return err
		}
		if _, err = tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("migration %s: %w", entry.Name(), err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO schema_migrations(name,sha256) VALUES($1,$2)`, entry.Name(), digest); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
