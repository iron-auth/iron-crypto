package utils_test

import (
	"testing"

	"github.com/iron-auth/iron-tokens/utils"
	a "github.com/james-elicx/go-utils/assert"
)

func TestBase64Encode(t *testing.T) {
	t.Parallel()

	encoded := utils.Base64Encode(HelloWorldString)

	a.Equals(t, encoded, HelloWorldBase64)
}

func TestBase64Decode(t *testing.T) {
	t.Parallel()

	decoded, err := utils.Base64Decode(HelloWorldBase64)

	a.Equals(t, err, nil)
	a.Equals(t, decoded, HelloWorldString)
}

func TestBase64DecodeError(t *testing.T) {
	t.Parallel()

	_, err := utils.Base64Decode("SGVsbG8gV29ybGQh!")

	a.Equals(t, err.Error(), "illegal base64 data at input byte 16")
}
