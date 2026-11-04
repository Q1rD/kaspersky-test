package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"threatservice/internal/domain"
	"threatservice/internal/threat"
	"time"
)

const testKey = "01234567890123456789012345678901"

type repo struct{ err error }

func (r repo) Create(_ context.Context, id string, in domain.Input) (domain.Threat, error) {
	return domain.Threat{MD5: id, Input: in, CreatedAt: time.Now(), UpdatedAt: time.Now()}, r.err
}
func (r repo) Update(c context.Context, id string, in domain.Input) (domain.Threat, error) {
	return r.Create(c, id, in)
}
func (r repo) Get(_ context.Context, id string) (domain.Threat, error) {
	return domain.Threat{}, domain.ErrNotFound
}
func (r repo) List(_ context.Context, f domain.Filter) ([]domain.Threat, error) { return nil, r.err }
func TestHTTPContract(t *testing.T) {
	e, err := New(threat.New(repo{}), testKey, time.Second, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"md5":"abcdef0123456789abcdef0123456789","name":"Trojan","platforms":["arch"]}`
	cases := []struct {
		name, method, path, body, key, media string
		status                               int
	}{
		{"create", "POST", "/info", valid, testKey, "application/json", 201},
		{"auth required", "POST", "/info", valid, "", "application/json", 401},
		{"wrong key", "PUT", "/info/abcdef0123456789abcdef0123456789", `{"name":"x"}`, "wrong", "application/json", 401},
		{"required name", "POST", "/info", `{"md5":"abcdef0123456789abcdef0123456789"}`, testKey, "application/json", 400},
		{"unknown field", "POST", "/info", `{"md5":"abcdef0123456789abcdef0123456789","name":"x","source":"x"}`, testKey, "application/json", 400},
		{"case ambiguity", "POST", "/info", `{"md5":"abcdef0123456789abcdef0123456789","name":"x","NAME":"y"}`, testKey, "application/json", 400},
		{"duplicate field", "POST", "/info", `{"name":"x","name":"y"}`, testKey, "application/json", 400},
		{"trailing JSON", "POST", "/info", valid + `{}`, testKey, "application/json", 400},
		{"null body", "POST", "/info", `null`, testKey, "application/json", 400},
		{"bad md5", "GET", "/info/nope", "", "", "", 400},
		{"missing", "GET", "/info/abcdef0123456789abcdef0123456789", "", "", "", 404},
		{"list", "GET", "/info?platforms=arch&platforms=ubuntu", "", "", "", 200},
		{"unknown platform", "GET", "/info?platforms=unknown", "", "", "", 400},
		{"empty platform", "GET", "/info?platforms=", "", "", "", 400},
		{"unknown param", "GET", "/info?platform_match=any", "", "", "", 400},
		{"bad limit", "GET", "/info?limit=0", "", "", "", 400},
		{"invalid limit", "GET", "/info?limit=abc", "", "", "", 400},
		{"repeated limit", "GET", "/info?limit=1&limit=2", "", "", "", 400},
		{"oversized", "POST", "/info", strings.Repeat("x", MaxBody+1), testKey, "application/json", 413},
		{"content type", "POST", "/info", valid, testKey, "text/plain", 415},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			if tc.key != "" {
				req.Header.Set("X-API-Key", tc.key)
			}
			if tc.media != "" {
				req.Header.Set("Content-Type", tc.media)
			}
			rr := httptest.NewRecorder()
			e.ServeHTTP(rr, req)
			if rr.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", rr.Code, tc.status, rr.Body.String())
			}
			if rr.Code >= 400 {
				var b struct {
					Message string `json:"message"`
				}
				if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil || b.Message == "" {
					t.Fatalf("invalid error: %s", rr.Body.String())
				}
			}
		})
	}
}
func TestInternalErrorIsRedacted(t *testing.T) {
	e, _ := New(threat.New(repo{err: errors.New("secret database password")}), testKey, time.Second, func(context.Context) error { return nil })
	r := httptest.NewRecorder()
	e.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/info", nil))
	if r.Code != 500 || strings.Contains(r.Body.String(), "password") {
		t.Fatal(r.Code, r.Body.String())
	}
}
