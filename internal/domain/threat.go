// Package domain contains transport-independent threat data and errors.
package domain

import (
	"errors"
	"time"
)

var (
	ErrInvalid      = errors.New("invalid request")
	ErrNotFound     = errors.New("threat not found")
	ErrConflict     = errors.New("threat already exists")
	ErrUnauthorized = errors.New("unauthorized")
)

type Input struct {
	Name        string
	Description *string
	Type        string
	Severity    string
	Platforms   []string
	FirstSeenAt *time.Time
}

type Threat struct {
	MD5 string
	Input
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Filter struct {
	Platforms     []string
	Limit, Offset int
}
type Page struct {
	Items         []Threat
	Limit, Offset int
	HasMore       bool
}
