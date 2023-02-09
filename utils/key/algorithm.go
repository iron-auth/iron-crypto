package key

type algorithm int64

const (
	AES256CBC algorithm = iota
	AES128CTR
	SHA256
)

type algorithmData struct {
	keyBits int
	ivBits  int
	name    string
}

var (
	algorithms = map[algorithm]algorithmData{
		AES256CBC: {256, 128, "AES-CBC"},
		AES128CTR: {128, 128, "AES-CTR"},
		SHA256:    {256, 0, "SHA-256"},
	}
)

// check algorithm is valid
func isAlgorithmValid(algo algorithm) bool {
	return algo == AES128CTR || algo == AES256CBC || algo == SHA256
}
