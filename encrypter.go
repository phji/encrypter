package encrypter

type Cipher int

const (
	AES_128_CBC Cipher = iota
	AES_256_CBC
)

type (
	Encrypter struct {
		key    string
		cipher Cipher
	}
)

func NewEncrypter(key string, cipher Cipher) *Encrypter {
	e := &Encrypter{key: key, cipher: cipher}

	if e.Supported(key, cipher) {
		return &Encrypter{key: key, cipher: cipher}
	}

	panic("The only supported ciphers are AES-128-CBC and AES-256-CBC with the correct key lengths.")
}

func (e *Encrypter) Supported(key string, cipher Cipher) bool {
	length := len(key)
	return (cipher == AES_128_CBC && length == 16) || (cipher == AES_256_CBC && length == 32)
}
