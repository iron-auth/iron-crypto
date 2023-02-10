package key

// The type of encryption algorithm to use.
type Algorithm int64

const (
	// AES-256-CBC.
	AES256CBC Algorithm = iota
	// AES-128-CTR.
	AES128CTR
	// SHA-256.
	SHA256
)

type algorithmData struct {
	keyBits int
	ivBits  int
	name    string
}

var (
	algorithms = map[Algorithm]algorithmData{
		AES256CBC: {256, 128, "AES-CBC"},
		AES128CTR: {128, 128, "AES-CTR"},
		SHA256:    {256, 0, "SHA-256"},
	}
)

// check algorithm is valid
func isAlgorithmValid(algo Algorithm) bool {
	return algo == AES128CTR || algo == AES256CBC || algo == SHA256
}
