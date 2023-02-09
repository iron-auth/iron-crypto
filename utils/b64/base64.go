package b64

import (
	"encoding/base64"
)

// Encode a string to base64
func Encode(data string) string {
	return base64.URLEncoding.EncodeToString([]byte(data))
}

// Decode a base64 string to a string
func Decode(data string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(data)
	return string(decoded), err
}
