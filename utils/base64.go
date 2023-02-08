package utils

import (
	"encoding/base64"
)

func Base64Encode(data string) string {
	return base64.URLEncoding.EncodeToString([]byte(data))
}

func Base64Decode(data string) (string, error) {
	decoded, err := base64.URLEncoding.DecodeString(data)
	return string(decoded), err
}
