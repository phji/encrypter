package encrypter

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

type (
	Encrypter struct {
		key string
	}
)

func NewEncrypter(key string) *Encrypter {
	decoded, _ := base64.StdEncoding.DecodeString(key)

	return &Encrypter{key: string(decoded)}
}

func (e *Encrypter) Encrypt(value string) string {
	iv, _ := e.RandomBytes(32)
	e.hash(base64.StdEncoding.EncodeToString(iv), value)

	return ""
}

func (e *Encrypter) Decrypt(payload string) string {
	json := e.getJsonPayload(payload);
	iv, _ := base64.StdEncoding.DecodeString(json.Iv)


	return string(iv)
}

type Payload struct {
	Iv string
	Value string
	Mac string
}

func (e *Encrypter) getJsonPayload(payload string ) Payload {
	decoded, _ := base64.StdEncoding.DecodeString(payload)

	var p Payload
	if err := json.Unmarshal(decoded, &p); err != nil {
		panic(err)
	}

	return p
}

func (e *Encrypter) RandomBytes(size int) (blk []byte, err error) {
	blk = make([]byte, size)
	_, err = rand.Read(blk)
	return
}

func (e *Encrypter) hash(iv string, value string) string {
	msg := iv + value

	h := hmac.New(sha256.New, []byte(e.key))
	h.Write([]byte(msg))

	return hex.EncodeToString(h.Sum(nil))
}
