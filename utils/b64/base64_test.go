package b64_test

import (
	"testing"

	"github.com/iron-auth/iron-tokens/utils/b64"
	a "github.com/james-elicx/go-utils/assert"
)

var (
	HelloWorldString = "Hello World!"
	HelloWorldBase64 = "SGVsbG8gV29ybGQh"
)

func TestEncode(t *testing.T) {
	t.Parallel()

	encoded := b64.Encode(HelloWorldString)

	a.Equals(t, encoded, HelloWorldBase64)
}

func TestDecode(t *testing.T) {
	t.Parallel()

	decoded, err := b64.Decode(HelloWorldBase64)

	a.Equals(t, err, nil)
	a.Equals(t, decoded, HelloWorldString)
}

func TestDecodeError(t *testing.T) {
	t.Parallel()

	_, err := b64.Decode("SGVsbG8gV29ybGQh!")

	a.EqualsError(t, err, "illegal base64 data at input byte 16")
}
