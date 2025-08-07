package auth

import (
	"errors"
	"net/http"
	"strings"
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
