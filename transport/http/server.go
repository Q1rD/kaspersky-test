// Package http adapts the generated OpenAPI contract to the threat service.
package http

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	oapimiddleware "github.com/oapi-codegen/echo-middleware"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"threatservice/internal/domain"
	"threatservice/internal/threat"
	"threatservice/transport/http/api"
	"time"
)

const MaxBody = 64 * 1024

func New(service *threat.Service, key string, timeout time.Duration, ping func(context.Context) error) (*echo.Echo, error) {
	if len(key) < 32 {
		return nil, errors.New("API key too short")
	}
	spec, err := api.GetSwagger()
	if err != nil {
		return nil, err
	}
	if err = spec.Validate(context.Background()); err != nil {
		return nil, err
	}
	spec.Servers = nil
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.IPExtractor = echo.ExtractIPDirect()
	e.HTTPErrorHandler = errorHandler
	e.Use(middleware.RecoverWithConfig(middleware.RecoverConfig{DisablePrintStack: true}), middleware.RequestID())
	digest := sha256.Sum256([]byte(key))
	authenticate := func(r *http.Request) bool {
		values := r.Header.Values("X-API-Key")
		if len(values) != 1 {
			return false
		}
		candidate := sha256.Sum256([]byte(values[0]))
		return subtle.ConstantTimeCompare(digest[:], candidate[:]) == 1
	}
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			start := time.Now()
			ctx, cancel := context.WithTimeout(c.Request().Context(), timeout)
			defer cancel()
			c.SetRequest(c.Request().WithContext(ctx))
			err := next(c)
			if err != nil {
				e.HTTPErrorHandler(err, c)
			}
			slog.Info("request", "method", c.Request().Method, "route", c.Path(), "status", c.Response().Status, "duration_ms", time.Since(start).Milliseconds(), "request_id", c.Response().Header().Get(echo.HeaderXRequestID))
			return nil
		}
	})
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			r := c.Request()
			if r.Method == http.MethodPost || r.Method == http.MethodPut {
				if !authenticate(r) {
					return domain.ErrUnauthorized
				}
				if r.Header.Get("Content-Encoding") != "" {
					return echo.NewHTTPError(415)
				}
				media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil || media != "application/json" {
					return echo.NewHTTPError(415)
				}
				if r.ContentLength > MaxBody {
					return echo.NewHTTPError(413)
				}
				body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
				if err != nil {
					return domain.ErrInvalid
				}
				if len(body) > MaxBody {
					return echo.NewHTTPError(413)
				}
				if err = checkJSON(body); err != nil {
					return domain.ErrInvalid
				}
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
			if strings.HasPrefix(r.URL.Path, "/info") {
				for k, v := range r.URL.Query() {
					if r.URL.Path != "/info" || r.Method != "GET" || k != "platforms" && k != "limit" && k != "offset" {
						return domain.ErrInvalid
					}
					if k != "platforms" && len(v) != 1 {
						return domain.ErrInvalid
					}
				}
			}
			return next(c)
		}
	})
	e.Use(oapimiddleware.OapiRequestValidatorWithOptions(spec, &oapimiddleware.Options{
		Skipper: func(c echo.Context) bool { return !strings.HasPrefix(c.Request().URL.Path, "/info") },
		Options: openapi3filter.Options{AuthenticationFunc: func(_ context.Context, in *openapi3filter.AuthenticationInput) error {
			if !authenticate(in.RequestValidationInput.Request) {
				return domain.ErrUnauthorized
			}
			return nil
		}},
		ErrorHandler: func(_ echo.Context, err *echo.HTTPError) error { return echo.NewHTTPError(err.Code) },
	}))
	api.RegisterHandlers(e, api.NewStrictHandler(&Handler{service: service}, nil))
	e.GET("/health/live", func(c echo.Context) error { return c.JSON(200, map[string]string{"status": "ok"}) })
	e.GET("/health/ready", func(c echo.Context) error {
		if err := ping(c.Request().Context()); err != nil {
			return echo.NewHTTPError(503)
		}
		return c.JSON(200, map[string]string{"status": "ready"})
	})
	e.GET("/openapi.json", func(c echo.Context) error { return c.JSON(200, spec) })
	return e, nil
}
func errorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}
	status := 500
	message := "internal server error"
	var he *echo.HTTPError
	switch {
	case errors.Is(err, domain.ErrInvalid):
		status = 400
		message = err.Error()
	case errors.Is(err, domain.ErrUnauthorized):
		status = 401
		message = "unauthorized"
	case errors.Is(err, domain.ErrNotFound):
		status = 404
		message = "threat not found"
	case errors.Is(err, domain.ErrConflict):
		status = 409
		message = "threat already exists"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		status = 503
		message = "service unavailable"
	case errors.As(err, &he):
		status = he.Code
		message = http.StatusText(status)
	}
	if status >= 500 {
		slog.Error("request failed", "request_id", c.Response().Header().Get(echo.HeaderXRequestID), "error", err)
	}
	_ = c.JSON(status, api.ErrorResponse{Message: message})
}

// checkJSON rejects duplicate keys, excessive nesting and trailing JSON values.
func checkJSON(body []byte) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON too deep")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			if depth == 0 {
				return errors.New("object required")
			}
			return nil
		}
		switch delimiter {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := k.(string)
				if !ok || keys[name] {
					return errors.New("duplicate JSON key")
				}
				keys[name] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			if depth == 0 {
				return errors.New("object required")
			}
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
