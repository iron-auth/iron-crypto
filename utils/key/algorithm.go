package key

type Algorithm int64

const (
	AES256CBC Algorithm = iota
	AES128CTR
	SHA256
)

type algorithmData struct {
	keyBits int
	ivBits  int
	name    string
}

var (
	AlgorithmData = map[Algorithm]algorithmData{
		AES256CBC: {256, 128, "AES-CBC"},
		AES128CTR: {128, 128, "AES-CTR"},
		SHA256:    {256, 0, "SHA-256"},
	}
)
