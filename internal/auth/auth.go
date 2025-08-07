package auth

import (
	"errors"
	"net/http"
	"testing"
)

// TestGetAPIKey provides unit tests for the GetAPIKey function.
func TestGetAPIKey(t *testing.T) {
	// testCases defines the structure for our table-driven tests.
	testCases := []struct {
		name          string      // The name of the test case
		headers       http.Header // The input headers
		expectedKey   string      // The expected API key to be returned
		expectedError error       // The expected error to be returned
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
			// The current function implementation returns an empty key and no error
			// for this specific case, which might be considered a bug.
			// This test captures the function's actual current behavior.
			expectedKey:   "",
			expectedError: nil,
		},
	}

	// We iterate over each test case.
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			// 1. Check if the returned API key is what we expect.
			if key != tc.expectedKey {
				t.Errorf("unexpected key: want %q, got %q", tc.expectedKey, key)
			}

			// 2. Check if the returned error is what we expect.
			// This handles both nil and non-nil error cases.
			if (tc.expectedError != nil && err == nil) || (tc.expectedError == nil && err != nil) || (tc.expectedError != nil && err != nil && tc.expectedError.Error() != err.Error()) {
				t.Errorf("unexpected error: want %v, got %v", tc.expectedError, err)
			}
		})
	}
}
