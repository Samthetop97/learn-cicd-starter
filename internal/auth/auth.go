package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// Define a package-level error for missing Authorization header
var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

// GetAPIKey extracts the API key from the Authorization header.
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "ApiKey" {
		return "", errors.New("malformed authorization header")
	}

	key := strings.TrimSpace(parts[1])
	return key, nil
}

// -----------------------------
// Unit tests for GetAPIKey
// -----------------------------

func TestGetAPIKey_ValidKey(t *testing.T) {
	headers := http.Header{
		"Authorization": []string{"ApiKey my-secret-key"},
	}
	key, err := GetAPIKey(headers)
	if key != "my-secret-key" {
		t.Errorf("expected key 'my-secret-key', got '%s'", key)
	}
	if err != nil {
		t.Errorf("expected no error, got '%v'", err)
	}
}

func TestGetAPIKey_MissingHeader(t *testing.T) {
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected ErrNoAuthHeaderIncluded, got '%v'", err)
	}
}
