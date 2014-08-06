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
// See also http://golang.org/pkg/net/http/#Request.SetBasicAuth
func Get(r *http.Request) (username, password []byte, err error) {
	// Retrieve the Authorization header and check whether it contains basic auth information
	const basicScheme string = "Basic "
	auth := r.Header.Get("Authorization")

	if !strings.HasPrefix(auth, basicScheme) {
		err = errors.New("No basic auth scheme found")
		return
	}

	str, err := base64.StdEncoding.DecodeString(auth[len(basicScheme):])
	if err != nil {
		err = errors.New("No valid base64 data in basic auth scheme found")
		return
	}

	// Split on the first ":" character only, with any subsequent colons assumed to be part
	// of the password. Note that the RFC2617 standard does not place any limitations on
	// allowable characters in the password.
	cred := bytes.SplitN(str, []byte(":"), 2)
	if len(cred) != 2 {
		err = errors.New("No valid basic auth scheme found")
		return
	}

	username, password = cred[0], cred[1]
	return
}
