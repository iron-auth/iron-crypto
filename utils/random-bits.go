package utils

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math"
)

type instance struct {
	bits int
	Size int
}

func NewRandomBits(bits int) (instance, error) {
	if bits < 1 {
		return instance{}, errors.New("bits size must be greater than 0")
	}

	size := int(math.Ceil(float64(bits) / 8))

	return instance{bits: bits, Size: size}, nil
}

func (b instance) getRandomBytes() ([]byte, error) {
	buffer := make([]byte, b.Size)
	_, err := rand.Read(buffer)

	return buffer, err
}

func (b instance) GetRandomBits() ([]byte, error) {
	return b.getRandomBytes()
}

func (b instance) BytesToHex(bytes []byte) string {
	hex := ""

	for _, bit := range bytes {
		hex += fmt.Sprintf("%02x", bit)
	}

	return hex
}

func (b instance) GetRandomSalt() (string, error) {
	bits, err := b.GetRandomBits()
	// TODO: Is there a way to force the reader to error to enter this block?
	if err != nil {
		return "", err
	}

	salt := b.BytesToHex(bits)

	if len(salt) != b.bits/4 {
		return "", errors.New("invalid salt length")
	}

	return salt, nil
}
