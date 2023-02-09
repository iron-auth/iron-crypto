package bits

import (
	"bytes"
)

// Pad the given message to the given block size.
func Pad(message []byte, blockSize int) []byte {
	length := blockSize - (len(message) % blockSize)
	text := bytes.Repeat([]byte{byte(length)}, length)

	return append(message, text...)
}

func Unpad(message []byte) []byte {
	messageLength := len(message)
	paddingLength := int(message[messageLength-1])

	return message[:messageLength-paddingLength]
}
