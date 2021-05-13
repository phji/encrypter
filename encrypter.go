package encrypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/elliotchance/phpserialize"
)

type (
	Encrypter struct {
		key []byte
	}
)

func NewEncrypter(key string) *Encrypter {
	decoded, _ := base64.StdEncoding.DecodeString(key)

	return &Encrypter{key: decoded}
}


func (e *Encrypter) Encrypt(value string) string {
	iv, _ := e.RandomBytes(16)
	encodedIv := base64.StdEncoding.EncodeToString(iv)

	c, err := aes.NewCipher(e.key)

	encrypter := cipher.NewCBCEncrypter(c, iv)

	out, err := phpserialize.Marshal(value, nil)
	if err != nil {
		panic(err)
	}

	padded := PadByPkcs7(out)

	encodedValue := make([]byte, len(padded))
	copy(encodedValue, padded)

	encrypter.CryptBlocks(encodedValue, encodedValue)

	b64encoded := base64.StdEncoding.EncodeToString(encodedValue)

	mac := e.hash(encodedIv, string(b64encoded))

	p := Payload{Iv: encodedIv, Value: b64encoded, Mac: mac}
	json, err := json.Marshal(p)
	if err != nil {
		panic(err)
	}

	return base64.StdEncoding.EncodeToString(json)
}

func (e *Encrypter) Decrypt(payload string) string {
	json := e.getJsonPayload(payload)

	iv, _ := base64.StdEncoding.DecodeString(json.Iv)

	block, err := aes.NewCipher(e.key); if err != nil {
		panic(err)
	}

	cipherText, _ := base64.StdEncoding.DecodeString(json.Value)
	if len(cipherText) < aes.BlockSize {
		panic("cipher text must be longer than blocksize")
	} else if len(cipherText) % aes.BlockSize != 0 {
		panic("cipher text must be multiple of blocksize(128bit)")
	}

	plainText := make([]byte, len(cipherText))

	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(plainText, cipherText)

	serialized := UnPadByPkcs7(plainText)

	var unserialized string
	phpserialize.Unmarshal(serialized, &unserialized)

	return unserialized
}

func PadByPkcs7(data []byte) []byte {
	padSize := aes.BlockSize
	if len(data) % aes.BlockSize != 0 {
		padSize = aes.BlockSize - (len(data)) % aes.BlockSize
	}

	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(data, pad...) // Dots represent it unpack Slice(pad) into individual bytes
}

func UnPadByPkcs7(data []byte) []byte {
	padSize := int(data[len(data) - 1])
	return data[:len(data) - padSize]
}


type Payload struct {
	Iv string `json:"iv"`
	Value string `json:"value"`
	Mac string `json:"mac"`
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
