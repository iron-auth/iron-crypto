package str

import (
	"encoding/base64"

	"github.com/iron-auth/iron-tokens"
)

// Encode a string to base64
func ToBase64(data string) string {
	return base64.URLEncoding.EncodeToString(ToBuffer(data))
}

// Decode a base64 string to a string
func FromBase64(data string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		return "", iron.ErrBase64Decode
	}
	return FromBuffer(decoded), nil
}
