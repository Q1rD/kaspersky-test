// Package threat validates and normalizes threat records before persistence.
package threat

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"threatservice/internal/domain"
	"time"
	"unicode/utf8"
)

type Repository interface {
	Create(context.Context, string, domain.Input) (domain.Threat, error)
	Get(context.Context, string) (domain.Threat, error)
	Update(context.Context, string, domain.Input) (domain.Threat, error)
	List(context.Context, domain.Filter) ([]domain.Threat, error)
}
type Service struct {
	repo Repository
	now  func() time.Time
}

func New(repo Repository) *Service { return &Service{repo: repo, now: time.Now} }

var parents = map[string]string{"windows": "", "linux": "", "arch": "linux", "ubuntu": "linux", "debian": "linux", "fedora": "linux", "macos": "", "android": "", "ios": ""}
var types = []string{"trojan", "worm", "ransomware", "spyware", "adware", "other", "unknown"}
var severities = []string{"low", "medium", "high", "critical", "unknown"}

func invalid(field string) error { return fmt.Errorf("%w: %s", domain.ErrInvalid, field) }
func MD5(value string) (string, error) {
	if len(value) != 32 {
		return "", invalid("md5")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", invalid("md5")
	}
	return strings.ToLower(value), nil
}

// Platforms expands ancestors only for writes. Query filters use expand=false.
func Platforms(values []string, expand bool) ([]string, error) {
	if len(values) > 32 {
		return nil, invalid("platforms")
	}
	set := map[string]bool{}
	for _, v := range values {
		parent, ok := parents[v]
		if !ok {
			return nil, invalid("platforms")
		}
		set[v] = true
		if expand && parent != "" {
			set[parent] = true
		}
	}
	result := make([]string, 0, len(set))
	for v := range set {
		result = append(result, v)
	}
	slices.Sort(result)
	return result, nil
}
func normalize(in domain.Input, now time.Time) (domain.Input, error) {
	in.Name = strings.TrimSpace(in.Name)
	if !utf8.ValidString(in.Name) || utf8.RuneCountInString(in.Name) < 1 || utf8.RuneCountInString(in.Name) > 255 || strings.ContainsRune(in.Name, 0) {
		return in, invalid("name")
	}
	if in.Description != nil && (!utf8.ValidString(*in.Description) || utf8.RuneCountInString(*in.Description) > 4096 || strings.ContainsRune(*in.Description, 0)) {
		return in, invalid("description")
	}
	if in.Type == "" {
		in.Type = "unknown"
	}
	if in.Severity == "" {
		in.Severity = "unknown"
	}
	if !slices.Contains(types, in.Type) {
		return in, invalid("type")
	}
	if !slices.Contains(severities, in.Severity) {
		return in, invalid("severity")
	}
	var err error
	in.Platforms, err = Platforms(in.Platforms, true)
	if err != nil {
		return in, err
	}
	if in.FirstSeenAt != nil {
		if in.FirstSeenAt.After(now) || in.FirstSeenAt.Year() < 1 || in.FirstSeenAt.Year() > 9999 {
			return in, invalid("first_seen_at")
		}
		t := in.FirstSeenAt.UTC().Truncate(time.Microsecond)
		in.FirstSeenAt = &t
	}
	return in, nil
}
func (s *Service) Create(ctx context.Context, md5 string, in domain.Input) (domain.Threat, error) {
	hash, err := MD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	in, err = normalize(in, s.now())
	if err != nil {
		return domain.Threat{}, err
	}
	return s.repo.Create(ctx, hash, in)
}
func (s *Service) Get(ctx context.Context, md5 string) (domain.Threat, error) {
	hash, err := MD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	return s.repo.Get(ctx, hash)
}
func (s *Service) Update(ctx context.Context, md5 string, in domain.Input) (domain.Threat, error) {
	hash, err := MD5(md5)
	if err != nil {
		return domain.Threat{}, err
	}
	in, err = normalize(in, s.now())
	if err != nil {
		return domain.Threat{}, err
	}
	return s.repo.Update(ctx, hash, in)
}
func (s *Service) List(ctx context.Context, f domain.Filter) (domain.Page, error) {
	if f.Limit < 1 || f.Limit > 100 || f.Offset < 0 || f.Offset > 2147483647 {
		return domain.Page{}, invalid("pagination")
	}
	var err error
	f.Platforms, err = Platforms(f.Platforms, false)
	if err != nil {
		return domain.Page{}, err
	}
	rows, err := s.repo.List(ctx, f)
	if err != nil {
		return domain.Page{}, err
	}
	if rows == nil {
		rows = []domain.Threat{}
	}
	more := len(rows) > f.Limit
	if more {
		rows = rows[:f.Limit]
	}
	return domain.Page{Items: rows, Limit: f.Limit, Offset: f.Offset, HasMore: more}, nil
}
