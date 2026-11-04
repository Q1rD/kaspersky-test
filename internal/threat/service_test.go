package threat

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"threatservice/internal/domain"
	"time"
)

type fakeRepo struct {
	got    domain.Threat
	filter domain.Filter
	err    error
	rows   []domain.Threat
}

func (r *fakeRepo) Create(_ context.Context, id string, in domain.Input) (domain.Threat, error) {
	r.got = domain.Threat{MD5: id, Input: in}
	return r.got, r.err
}
func (r *fakeRepo) Get(_ context.Context, id string) (domain.Threat, error) { return r.got, r.err }
func (r *fakeRepo) Update(c context.Context, id string, in domain.Input) (domain.Threat, error) {
	return r.Create(c, id, in)
}
func (r *fakeRepo) List(_ context.Context, f domain.Filter) ([]domain.Threat, error) {
	r.filter = f
	return r.rows, r.err
}
func TestNormalization(t *testing.T) {
	r := &fakeRepo{}
	s := New(r)
	first := time.Date(2020, 1, 1, 10, 0, 0, 123456789, time.FixedZone("+3", 10800))
	got, err := s.Create(context.Background(), "ABCDEF0123456789ABCDEF0123456789", domain.Input{Name: "  Trojan  ", Platforms: []string{"ubuntu", "arch", "arch"}, FirstSeenAt: &first})
	if err != nil {
		t.Fatal(err)
	}
	if got.MD5 != "abcdef0123456789abcdef0123456789" || got.Name != "Trojan" || got.Type != "unknown" || got.Severity != "unknown" {
		t.Fatalf("unexpected result: %+v", got)
	}
	if !reflect.DeepEqual(got.Platforms, []string{"arch", "linux", "ubuntu"}) {
		t.Fatal(got.Platforms)
	}
	if got.FirstSeenAt.Location() != time.UTC || got.FirstSeenAt.Nanosecond() != 123456000 {
		t.Fatal(got.FirstSeenAt)
	}
	if first.Nanosecond() != 123456789 {
		t.Fatal("mutated caller time")
	}
}
func TestInvalidInput(t *testing.T) {
	future := time.Now().Add(time.Hour)
	for _, in := range []domain.Input{{Name: " \t "}, {Name: "x", Type: "invalid"}, {Name: "x", Severity: "invalid"}, {Name: "x", Platforms: []string{"Arch"}}, {Name: "x", FirstSeenAt: &future}, {Name: "x\x00"}} {
		_, err := New(&fakeRepo{}).Create(context.Background(), "abcdef0123456789abcdef0123456789", in)
		if !errors.Is(err, domain.ErrInvalid) {
			t.Fatalf("expected invalid for %+v: %v", in, err)
		}
	}
	for _, id := range []string{"", "fffffffffffffffffffffffffffffffg", "fffffffffffffffffffffffffffffff"} {
		if _, err := MD5(id); !errors.Is(err, domain.ErrInvalid) {
			t.Fatal(id, err)
		}
	}
}
func TestFilterDoesNotExpand(t *testing.T) {
	r := &fakeRepo{rows: []domain.Threat{{MD5: "1"}, {MD5: "2"}}}
	page, err := New(r).List(context.Background(), domain.Filter{Platforms: []string{"arch", "ubuntu"}, Limit: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.filter.Platforms, []string{"arch", "ubuntu"}) || len(page.Items) != 1 || !page.HasMore {
		t.Fatal(r.filter, page)
	}
}
func TestRepositoryErrorsPropagate(t *testing.T) {
	want := errors.New("connection lost")
	_, err := New(&fakeRepo{err: want}).Create(context.Background(), "abcdef0123456789abcdef0123456789", domain.Input{Name: "x"})
	if !errors.Is(err, want) {
		t.Fatal(err)
	}
}
