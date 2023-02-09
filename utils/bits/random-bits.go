package bits

import (
	"crypto/rand"
	"fmt"
	"math"

	"github.com/iron-auth/iron-tokens"
)

// Check if the given size is valid
func isValidSize(size int) error {
	if size < 1 {
		return iron.ErrInvalidBitsSize
	}

	// this is the max size of an `ArrayBuffer` in javascript (2^31 - 1) on 32-bit systems
	// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Errors/Invalid_array_length
	if size > (2147483648 / 8) {
		return iron.ErrInvalidBitsSize
	}

	return nil
}

// Generate a random bytes array for the given number of bytes
func RandomBytes(size int) ([]byte, error) {
	if err := isValidSize(size); err != nil {
		return nil, err
	}

	buffer := make([]byte, size)
	_, err := rand.Read(buffer)
	if err != nil {
		return nil, iron.ErrGeneratingBytes
	}

	return buffer, nil
}

// Generate a random bytes array for the given number of bits
func RandomBits(bits int) ([]byte, error) {
	size := int(math.Ceil(float64(bits) / 8))

	return RandomBytes(size)
}

// Convert a bytes array to a hex string
func BytesToHex(bytes []byte) string {
	hex := ""

	for _, bit := range bytes {
		hex += fmt.Sprintf("%02x", bit)
	}

	return hex
}

// Generate a random salt for the given number of bits
func RandomSalt(bits int) (string, error) {
	b, err := RandomBits(bits)
	// TODO: Is there a way to force the reader to error to enter this block during tests?
	if err != nil {
		return "", iron.ErrGeneratingSalt
	}

	salt := BytesToHex(b)

	return salt, nil
}
