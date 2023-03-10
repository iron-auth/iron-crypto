package bits_test

import (
	"testing"

	"github.com/iron-auth/iron-crypto/bits"
	"github.com/iron-auth/iron-crypto/ironerrors"
	a "github.com/james-elicx/go-utils/assert"
)

const (
	HelloWorldString = "Hello World!"
	HelloWorldHex    = "48656c6c6f20576f726c6421"
)

var HelloWorldBytes = []byte{72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33}

func TestSizeError(t *testing.T) {
	t.Parallel()

	_, err := bits.RandomBits(0)
	a.EqualsError(t, err, ironerrors.ErrInvalidBitsSize)

	_, err = bits.RandomBits(99999999999999)
	a.EqualsError(t, err, ironerrors.ErrInvalidBitsSize)

	_, err = bits.RandomBytes(0)
	a.EqualsError(t, err, ironerrors.ErrInvalidBitsSize)

	_, err = bits.RandomBytes(99999999999999)
	a.EqualsError(t, err, ironerrors.ErrInvalidBitsSize)

	_, err = bits.RandomSalt(0)
	a.EqualsError(t, err, ironerrors.ErrInvalidBitsSize)
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
