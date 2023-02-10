package str

// Encode a string to a buffer.
func ToBuffer(data string) []byte {
	return []byte(data)
}

// Decode a buffer to a string.
func FromBuffer(data []byte) string {
	return string(data)
}

// Make a new buffer of the given length.
func MakeBuffer(length int) []byte {
	return make([]byte, length)
}
