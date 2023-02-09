package str_test

import (
	"testing"

	"github.com/iron-auth/iron-tokens"
	"github.com/iron-auth/iron-tokens/utils/str"
	a "github.com/james-elicx/go-utils/assert"
)

const (
	HelloWorldString = "Hello World!"
	HelloWorldBase64 = "SGVsbG8gV29ybGQh"
)

func TestEncode(t *testing.T) {
	t.Parallel()

	encoded := str.ToBase64(HelloWorldString)

	a.Equals(t, encoded, HelloWorldBase64)
}

func TestDecode(t *testing.T) {
	t.Parallel()

	decoded, err := str.FromBase64(HelloWorldBase64)

	a.Equals(t, err, nil)
	a.Equals(t, decoded, HelloWorldString)
}

func TestDecodeError(t *testing.T) {
	t.Parallel()

	_, err := str.FromBase64("SGVsbG8gV29ybGQh!")

	a.EqualsError(t, err, iron.ErrBase64Decode)
}
