package crypto

import (
	"bytes"
	"crypto/rand"
)

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	var padding = blockSize - len(ciphertext)%blockSize
	var padTexts = bytes.Repeat([]byte{0}, padding) //用0去填充
	return append(ciphertext, padTexts...)
}

func ZeroUnPadding(origData []byte) []byte {
	return bytes.TrimFunc(origData,
		func(r rune) bool {
			return r == rune(0)
		})
}

func Pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	var padding = blockSize - len(ciphertext)%blockSize //需要padding的数目
	var padTexts = bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padTexts...)
}

func Pkcs7UnPadding(origData []byte) []byte {
	var length = len(origData)
	var paddingBytes = int(origData[length-1])
	return origData[:(length - paddingBytes)]
}

func Iso10126Padding(ciphertext []byte, blockSize int) ([]byte, error) {
	var paddingBytes = blockSize - len(ciphertext)%blockSize
	paddingSlice := make([]byte, paddingBytes-1)
	_, err := rand.Read(paddingSlice)
	if err != nil {
		return nil, err
	}
	paddingSlice = append(paddingSlice, byte(paddingBytes))
	return append(ciphertext, paddingSlice...), nil
}

func Iso10126UnPadding(origData []byte) []byte {
	var dataLen = len(origData)
	var paddingBytes = int(origData[dataLen-1])
	return origData[0 : dataLen-paddingBytes]
}

func AnsiX923Padding(ciphertext []byte, blockSize int) []byte {
	var paddingBytes = blockSize - len(ciphertext)%blockSize
	paddingSlice := append(bytes.Repeat([]byte{byte(0)}, paddingBytes-1), byte(paddingBytes))
	return append(ciphertext, paddingSlice...)
}

func AnsiX923UnPadding(origData []byte) []byte {
	var dataLen = len(origData)
	var paddingBytes = int(origData[dataLen-1])
	return origData[0 : dataLen-paddingBytes]
}
