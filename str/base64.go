package str

import (
	"encoding/base64"
	"strings"

	"github.com/iron-auth/iron-crypto/ironerrors"
)

// Encode a string to base64
func ToBase64(data []byte) string {
	b64 := base64.StdEncoding.EncodeToString(data)

	b64 = strings.ReplaceAll(b64, "+", "-")
	b64 = strings.ReplaceAll(b64, "/", "_")
	b64 = strings.ReplaceAll(b64, "=", "")

	return b64
}

// Decode a base64 string to a string
func FromBase64(data string) ([]byte, error) {
	corrected := data

	corrected = strings.ReplaceAll(corrected, "-", "+")
	corrected = strings.ReplaceAll(corrected, "_", "/")

	corrected = corrected + strings.Repeat("=", (4-(len(data)%4))%4)

	decoded, err := base64.StdEncoding.DecodeString(corrected)
	if err != nil {
		return nil, ironerrors.ErrBase64Decode
	}
	return decoded, nil
}
