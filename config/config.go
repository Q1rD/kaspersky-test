// Package config loads public YAML settings and separately mounted secrets.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTP struct {
		Address        string        `yaml:"address"`
		RequestTimeout time.Duration `yaml:"request_timeout"`
	} `yaml:"http"`
	Postgres struct {
		Host         string `yaml:"host"`
		Port         int    `yaml:"port"`
		Database     string `yaml:"database"`
		User         string `yaml:"user"`
		PasswordFile string `yaml:"password_file"`
		MaxConns     int32  `yaml:"max_conns"`
		SSLMode      string `yaml:"sslmode"`
	} `yaml:"postgres"`
	APIKeyFile string `yaml:"api_key_file"`
}

func ReadSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	value := strings.TrimSpace(string(b))
	if len(value) < 32 || len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("secret must contain 32..512 bytes on one line")
	}
	return value, nil
}
func Load() (Config, error) {
	var c Config
	path := os.Getenv("CONFIG_FILE")
	if path == "" {
		path = "config/config.yaml"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if user := os.Getenv("DB_USER"); user != "" {
		c.Postgres.User = user
	}
	if file := os.Getenv("DB_PASSWORD_FILE"); file != "" {
		c.Postgres.PasswordFile = file
	}
	if host := os.Getenv("DB_HOST"); host != "" {
		c.Postgres.Host = host
	}
	if c.HTTP.Address == "" || c.HTTP.RequestTimeout <= 0 || c.Postgres.Host == "" || c.Postgres.Port < 1 || c.Postgres.Port > 65535 || c.Postgres.Database == "" || c.Postgres.User == "" || c.Postgres.MaxConns < 1 || c.Postgres.MaxConns > 100 {
		return c, errors.New("invalid configuration")
	}
	if c.Postgres.SSLMode != "disable" && c.Postgres.SSLMode != "verify-full" {
		return c, errors.New("unsupported PostgreSQL sslmode")
	}
	return c, nil
}
func (c Config) DSN() (string, error) {
	password, err := ReadSecret(c.Postgres.PasswordFile)
	if err != nil {
		return "", err
	}
	u := url.URL{Scheme: "postgres", User: url.UserPassword(c.Postgres.User, password), Host: c.Postgres.Host + ":" + strconv.Itoa(c.Postgres.Port), Path: "/" + c.Postgres.Database}
	q := u.Query()
	q.Set("sslmode", c.Postgres.SSLMode)
	q.Set("connect_timeout", "5")
	u.RawQuery = q.Encode()
	return u.String(), nil
}
