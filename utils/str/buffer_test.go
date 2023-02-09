package str_test

import (
	"testing"

	"github.com/iron-auth/iron-tokens/utils/str"
	a "github.com/james-elicx/go-utils/assert"
)

func TestToBuffer(t *testing.T) {
	t.Parallel()

	encoded := str.ToBuffer("Hello World!")
	a.EqualsArray(t, encoded, []byte("Hello World!"))
}

func TestFromBuffer(t *testing.T) {
	t.Parallel()

	decoded := str.FromBuffer([]byte("Hello World!"))
	a.Equals(t, decoded, "Hello World!")
}

func TestMakeBuffer(t *testing.T) {
	t.Parallel()

	buffer := str.MakeBuffer(10)
	a.Equals(t, len(buffer), 10)
}
