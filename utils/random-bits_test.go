package utils_test

import (
	"testing"

	"github.com/iron-auth/iron-tokens/utils"
	a "github.com/james-elicx/go-utils/assert"
)

// `Hello World!`
var HelloWorldString = "Hello World!"
var HelloWorldBytes = []byte{72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33}
var HelloWorldHex = "48656c6c6f20576f726c6421"
var HelloWorldBase64 = "SGVsbG8gV29ybGQh"

func TestSize(t *testing.T) {
	t.Parallel()

	bits, err := utils.NewRandomBits(256)

	a.Equals(t, err, nil)
	a.Equals(t, bits.Size, 32)
}

func TestSizeError(t *testing.T) {
	t.Parallel()

	_, err := utils.NewRandomBits(0)

	a.Equals(t, err.Error(), "bits size must be greater than 0")
}

func TestGetRandomBits(t *testing.T) {
	t.Parallel()

	bits, _ := utils.NewRandomBits(256)
	bytes, err := bits.GetRandomBits()

	a.Equals(t, err, nil)
	a.Equals(t, len(bytes), 32)
}

func TestBytesToHex(t *testing.T) {
	t.Parallel()

	bits, _ := utils.NewRandomBits(256)
	hex := bits.BytesToHex(HelloWorldBytes)

	a.Equals(t, len(hex), 24)
	a.Equals(t, hex, HelloWorldHex)
}

func TestGetRandomSalt(t *testing.T) {
	t.Parallel()

	bits, _ := utils.NewRandomBits(256)
	salt, err := bits.GetRandomSalt()

	a.Equals(t, err, nil)
	a.Equals(t, len(salt), 64)
}

func TestGetRandomSaltError(t *testing.T) {
	t.Parallel()

	bits, _ := utils.NewRandomBits(256)
	bits.Size = 0
	_, err := bits.GetRandomSalt()

	a.Equals(t, err.Error(), "invalid salt length")
}
