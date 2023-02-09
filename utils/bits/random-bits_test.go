package bits_test

import (
	"testing"

	"github.com/iron-auth/iron-tokens/utils/bits"
	a "github.com/james-elicx/go-utils/assert"
)

var (
	HelloWorldString = "Hello World!"
	HelloWorldBytes  = []byte{72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33}
	HelloWorldHex    = "48656c6c6f20576f726c6421"
)

func TestSizeError(t *testing.T) {
	t.Parallel()

	_, err := bits.RandomBits(0)
	a.EqualsError(t, err, "bits size must be greater than 0")

	_, err = bits.RandomBits(99999999999999)
	a.EqualsError(t, err, "bits size must be less than 2147483648")

	_, err = bits.RandomBytes(0)
	a.EqualsError(t, err, "bits size must be greater than 0")

	_, err = bits.RandomBytes(99999999999999)
	a.EqualsError(t, err, "bits size must be less than 2147483648")
}

func TestGetRandomBits(t *testing.T) {
	t.Parallel()

	bytes, err := bits.RandomBits(256)

	a.Equals(t, err, nil)
	a.Equals(t, len(bytes), 32)
}

func TestBytesToHex(t *testing.T) {
	t.Parallel()

	hex := bits.BytesToHex(HelloWorldBytes)

	a.Equals(t, len(hex), 24)
	a.Equals(t, hex, HelloWorldHex)
}

func TestGetRandomSalt(t *testing.T) {
	t.Parallel()

	salt, err := bits.RandomSalt(256)

	a.Equals(t, err, nil)
	a.Equals(t, len(salt), 64)
}
