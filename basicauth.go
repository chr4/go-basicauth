package basicauth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

// RetrieveCredentials() gets HTTP Basic Auth credentials from a HTTP request
// Courtesty goes to https://github.com/goji/httpauth
func RetrieveCredentials(r *http.Request) (username, password []byte, err error) {
	// Retrieve the Authorization header and check whether it contains basic auth information
	const basicScheme string = "Basic "
	auth := r.Header.Get("Authorization")

	if !strings.HasPrefix(auth, basicScheme) {
		return "", "", errors.New("No basic auth scheme found")
	}

	str, err := base64.StdEncoding.DecodeString(auth[len(basicScheme):])
	if err != nil {
		return "", "", errors.New("No valid base64 data in basic auth scheme found")
	}

	// Split on the first ":" character only, with any subsequent colons assumed to be part
	// of the password. Note that the RFC2617 standard does not place any limitations on
	// allowable characters in the password.
	// Also make username lowercase
	cred := bytes.SplitN(str, []byte(":"), 2)
	return cred[0], cred[1], nil
}
