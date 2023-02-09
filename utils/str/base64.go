package str

import (
	"encoding/base64"
)

// Encode a string to base64
func ToBase64(data string) string {
	return base64.URLEncoding.EncodeToString([]byte(data))
}

// Decode a base64 string to a string
func FromBase64(data string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(data)
	return string(decoded), err
}
