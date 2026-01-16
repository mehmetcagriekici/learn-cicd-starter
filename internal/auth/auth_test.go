package auth

import(
	"errors"
	"net/http"
	"testing"
)

var testHeaders = make(http.Header)

func TestGetAPIKeyAuthValid(t *testing.T) {
	testHeaders.Set("Authorization", "ApiKey valid_api_key")
	exp := "valid_api_key"
	res, err := GetAPIKey(testHeaders)
	if err != nil {
		t.Errorf("Unexpected error: %v with valid auth and api key.\n", err)
	}

	if res != exp {
		t.Errorf("Expected: %s, Got: %s.\n", exp, res)
	}
}

func TestGetGetAPIKeyNoAuth(t *testing.T) {
	testHeaders.Del("Authorization")
	exp := ""
	res, err := GetAPIKey(testHeaders)
	if !errors.Is(err, ErrNoAuthHeaderIncluded) {
		t.Errorf("Unexpected error! Expected error: %v, got: %v with no Authorization header.\n", ErrNoAuthHeaderIncluded, err)
	}

	if res != exp {
		t.Errorf("Expected result to be an empty string with no Authorization header.\n")
	}
}

func TestGetAPIKeyMalformed(t *testing.T) {
	testHeaders.Set("Authorization", "malformed authorization header")
	exp := ""
	res, err := GetAPIKey(testHeaders)
	if err.Error() != "malformed authorization header" {
	        t.Errorf("Unexpected error for malformed authorization header! %v\n", err)	
	}

	if res != exp {
		t.Errorf("Results is expected to be an empty string with malformed authorization header.\n")
	}
}
