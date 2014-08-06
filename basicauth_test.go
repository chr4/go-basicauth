package basicauth

import (
	"net/http"
	"testing"
)

// @todo rewrite tests
func TestGet(t *testing.T) {
	var header map[string][]string

	req, err := http.NewRequest("GET", "https://example.com/signup", nil)
	if err != nil {
		t.Error("getFromRequest(): Error creating HTTP request: %v", err)
	}

	// Test without HTTP Basic Auth header
	if _, _, err := Get(req); err == nil {
		t.Error("getFromRequest(): Didn't fail when not specifying 'HTTP Basic Auth' header")
	}

	// Test with invalid Authorization header
	header = map[string][]string{
		"Authorization": {"INVALID AUTH_HEADER"},
	}
	req.Header = header
	if _, _, err := Get(req); err == nil {
		t.Error("getFromRequest(): Didn't fail when using invalid 'Authorization' header")
	}

	// Test with invalid HTTP Basic Auth header
	header = map[string][]string{
		"Authorization": {"Basic INVALID"},
	}
	req.Header = header
	if _, _, err := Get(req); err == nil {
		t.Error("getFromRequest(): Didn't fail when using invalid 'HTTP Basic Auth' header")
	}

	// Test valid HTTP Basic Auth header
	req.SetBasicAuth("sarah", "i love icecream")
	username, password, err := Get(req)
	if err != nil {
		t.Error("getFromRequest(): Didn't succeed with valid HTTP Basic Auth header")
	}
	if string(username) != "sarah" {
		t.Error("Username didn't match")
	}
	if string(password) != "i love icecream" {
		t.Error("Password didn't match")
	}
}
