package tests

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"reflect"
	"sync"
	"testing"
	"threatservice/infra/postgres"
	"threatservice/internal/domain"
	"threatservice/internal/threat"
	"threatservice/migrations"
	"time"
)

func TestPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to an isolated PostgreSQL database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `DO $$ BEGIN CREATE ROLE threat_app; EXCEPTION WHEN duplicate_object THEN NULL; END $$`)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrations.Up(ctx, conn.Conn()); err != nil {
		t.Fatal(err)
	}
	if err = migrations.Up(ctx, conn.Conn()); err != nil {
		t.Fatal("migration repeat:", err)
	}
	conn.Release()
	if _, err = pool.Exec(ctx, `TRUNCATE threats`); err != nil {
		t.Fatal(err)
	}
	s := threat.New(postgres.New(pool))
	id := "abcdef0123456789abcdef0123456789"
	var wg sync.WaitGroup
	out := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Create(ctx, id, domain.Input{Name: "Trojan", Platforms: []string{"arch"}})
			out <- err
		}()
	}
	wg.Wait()
	close(out)
	success, conflict := 0, 0
	for err := range out {
		if err == nil {
			success++
		} else if errors.Is(err, domain.ErrConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || conflict != 11 {
		t.Fatal(success, conflict)
	}
	original, err := s.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	same, err := s.Update(ctx, id, domain.Input{Name: "Trojan", Platforms: []string{"arch"}})
	if err != nil || !same.UpdatedAt.Equal(original.UpdatedAt) {
		t.Fatal("non-idempotent update", err)
	}
	description := "details"
	changed, err := s.Update(ctx, id, domain.Input{Name: "Changed", Description: &description, Platforms: []string{"ubuntu"}})
	if err != nil || !changed.UpdatedAt.After(original.UpdatedAt) || !changed.CreatedAt.Equal(original.CreatedAt) {
		t.Fatal("update metadata", err)
	}
	if !reflect.DeepEqual(changed.Platforms, []string{"linux", "ubuntu"}) {
		t.Fatal(changed.Platforms)
	}
	for _, q := range []struct {
		p     []string
		count int
	}{{[]string{"linux"}, 1}, {[]string{"arch"}, 0}, {[]string{"arch", "ubuntu"}, 1}, {[]string{"windows"}, 0}} {
		page, err := s.List(ctx, domain.Filter{Platforms: q.p, Limit: 20})
		if err != nil || len(page.Items) != q.count {
			t.Fatal(q, page, err)
		}
	}
	cleared, err := s.Update(ctx, id, domain.Input{Name: "reset"})
	if err != nil || cleared.Description != nil || len(cleared.Platforms) != 0 || cleared.Type != "unknown" {
		t.Fatal(cleared, err)
	}
	_, err = s.Update(ctx, "00000000000000000000000000000000", domain.Input{Name: "x"})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatal(err)
	}
	for _, id := range []string{"00000000000000000000000000000001", "00000000000000000000000000000002"} {
		if _, err = s.Create(ctx, id, domain.Input{Name: "page"}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.List(ctx, domain.Filter{Limit: 2})
	if err != nil || len(page.Items) != 2 || !page.HasMore {
		t.Fatal(page, err)
	}
	// Verify the runtime role cannot change schema or delete data.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE threat_app`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `SELECT md5 FROM threats`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE forbidden(id int)`); err == nil {
		t.Fatal("runtime role can create tables")
	}
	// An actual closed pool must not be mapped to a missing row or conflict.
	tx.Rollback(ctx)
	pool.Close()
	short, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	_, err = s.Create(short, "00000000000000000000000000000003", domain.Input{Name: "x"})
	if err == nil || errors.Is(err, domain.ErrConflict) || errors.Is(err, domain.ErrNotFound) {
		t.Fatal("database outage misclassified", err)
	}
}
