// Package secret generates and hashes high-entropy tokens (authorization
// codes, JWT ids, password-reset tokens).
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// tokenBytes is 256 bits of entropy — enough that the tokens produced here need
// no slow KDF when stored (see Hash).
const tokenBytes = 32

// NewToken returns a URL-safe random string.
func NewToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Hash is the at-rest form of a token issued by NewToken, so a dump of the
// store holding it is not a set of usable credentials.
//
// A fast hash is correct here and bcrypt would be wrong: these tokens are 256
// bits of crypto/rand, so there is nothing to brute-force and nothing for a
// slow KDF to buy. (bcrypt is required for *passwords* precisely because
// passwords are low-entropy.)
func Hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
