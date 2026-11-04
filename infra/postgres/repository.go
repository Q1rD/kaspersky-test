// Package postgres implements threat persistence using parameterized SQL.
package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"threatservice/internal/domain"
)

type Repository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

const columns = `md5,name,description,type,severity,platforms,first_seen_at,created_at,updated_at`

func scan(row pgx.Row) (domain.Threat, error) {
	var t domain.Threat
	err := row.Scan(&t.MD5, &t.Name, &t.Description, &t.Type, &t.Severity, &t.Platforms, &t.FirstSeenAt, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, domain.ErrNotFound
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && pgerr.Code == "23505" && pgerr.ConstraintName == "threats_pkey" {
		return t, domain.ErrConflict
	}
	t.CreatedAt = t.CreatedAt.UTC()
	t.UpdatedAt = t.UpdatedAt.UTC()
	if t.FirstSeenAt != nil {
		v := t.FirstSeenAt.UTC()
		t.FirstSeenAt = &v
	}
	return t, err
}
func (r *Repository) Create(ctx context.Context, md5 string, in domain.Input) (domain.Threat, error) {
	return scan(r.pool.QueryRow(ctx, `INSERT INTO threats(md5,name,description,type,severity,platforms,first_seen_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,statement_timestamp(),statement_timestamp()) RETURNING `+columns, md5, in.Name, in.Description, in.Type, in.Severity, in.Platforms, in.FirstSeenAt))
}
func (r *Repository) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	return scan(r.pool.QueryRow(ctx, `SELECT `+columns+` FROM threats WHERE md5=$1`, md5))
}
func (r *Repository) Update(ctx context.Context, md5 string, in domain.Input) (domain.Threat, error) {
	return scan(r.pool.QueryRow(ctx, `UPDATE threats SET name=$2,description=$3,type=$4,severity=$5,platforms=$6,first_seen_at=$7,
 updated_at=CASE WHEN ROW(name,description,type,severity,platforms,first_seen_at) IS DISTINCT FROM ROW($2::text,$3::text,$4::text,$5::text,$6::text[],$7::timestamptz) THEN greatest(clock_timestamp(),updated_at+interval '1 microsecond') ELSE updated_at END
 WHERE md5=$1 RETURNING `+columns, md5, in.Name, in.Description, in.Type, in.Severity, in.Platforms, in.FirstSeenAt))
}
func (r *Repository) List(ctx context.Context, f domain.Filter) ([]domain.Threat, error) {
	query := `SELECT ` + columns + ` FROM threats`
	args := []any{f.Limit + 1, f.Offset}
	if len(f.Platforms) > 0 {
		query += ` WHERE platforms && $3::text[]`
		args = append(args, f.Platforms)
	}
	rows, err := r.pool.Query(ctx, query+` ORDER BY created_at DESC,md5 ASC LIMIT $1 OFFSET $2`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.Threat, 0, f.Limit+1)
	for rows.Next() {
		t, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
