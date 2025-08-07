package auth

import (
	"errors"
	"net/http"
	"testing"
)

// TestGetAPIKey provides unit tests for the GetAPIKey function.
func TestGetAPIKey(t *testing.T) {
	testCases := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid API Key - happy path",
			headers: http.Header{
				"Authorization": []string{"ApiKey my-secret-api-key"},
			},
			expectedKey:   "my-secret-api-key",
			expectedError: nil,
		},
		{
			name:          "No Authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed header - incorrect prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer my-secret-api-key"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed header - no key value",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name: "Malformed header - empty key value",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey:   "",
			expectedError: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			if key != tc.expectedKey {
				t.Errorf("unexpected key: want %q, got %q", tc.expectedKey, key)
			}

			if (tc.expectedError != nil && err == nil) ||
				(tc.expectedError == nil && err != nil) ||
				(tc.expectedError != nil && err != nil && tc.expectedError.Error() != err.Error()) {
				t.Errorf("unexpected error: want %v, got %v", tc.expectedError, err)
			}
		})
	}
}
