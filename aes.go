package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func AesEnc(plainText, key, iv []byte, mode modeWay, padding paddingWay) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	var paddingText []byte
	switch padding {
	case Pkcs5, Pkcs7: // pkcs5 is a subset of pkcs7, there is no difference
		paddingText = Pkcs7Padding(plainText, blockSize)
	case Zero:
		paddingText = ZeroPadding(plainText, blockSize)
	case None:
		paddingText = plainText
		if len(paddingText)%blockSize != 0 {
			return nil, fmt.Errorf("input not full blocks err, if chose None(no paddingWay), the input text must be a multiple of block size:[%v]", blockSize)
		}
	case ISO10126:
		paddingText, err = Iso10126Padding(plainText, blockSize)
		if err != nil {
			return nil, err
		}
	case AnsiX923:
		paddingText = AnsiX923Padding(plainText, blockSize)
	default:
		return nil, fmt.Errorf("please choose the correct paddingWay way,only supports Pkcs5 Pkcs7 Zero None ISO10126 AnsiX923")
	}

	var cipherText = make([]byte, len(paddingText))
	if mode != ECB && len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size[%v]", blockSize)
	}

	switch mode {
	case CBC:
		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(cipherText, paddingText)
	case ECB:
		tempText := make([]byte, blockSize+len(paddingText))
		for i := 0; i < len(paddingText); i += blockSize {
			block.Encrypt(tempText[i+blockSize:], paddingText[i:i+blockSize])
		}
		cipherText = tempText[blockSize:]
	case CFB:
		mode := cipher.NewCFBEncrypter(block, iv)
		mode.XORKeyStream(cipherText, paddingText)
	case OFB:
		mode := cipher.NewOFB(block, iv)
		mode.XORKeyStream(cipherText, paddingText)
	case CTR:
		mode := cipher.NewCTR(block, iv)
		mode.XORKeyStream(cipherText, paddingText)
	default:
		return nil, fmt.Errorf("please choose the correct encryption modeWay,only supports CBC ECB CFB OFB CTR")
	}

	return cipherText, nil
}

func AesDec(cipherText, key, iv []byte, mode modeWay, padding paddingWay) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	var paddingText = make([]byte, len(cipherText))
	if mode != ECB && len(iv) != blockSize {
		return nil, fmt.Errorf("IV length must equal block size[%v]", blockSize)
	}

	switch mode {
	case CBC:
		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(paddingText, cipherText)
	case ECB:
		for i := 0; i < len(cipherText); i += blockSize {
			block.Decrypt(paddingText[i:i+blockSize], cipherText[i:i+blockSize])
		}
	case CFB:
		mode := cipher.NewCFBDecrypter(block, iv)
		mode.XORKeyStream(paddingText, cipherText)
	case OFB:
		mode := cipher.NewOFB(block, iv)
		mode.XORKeyStream(paddingText, cipherText)
	case CTR:
		mode := cipher.NewCTR(block, iv)
		mode.XORKeyStream(paddingText, cipherText)
	default:
		return nil, fmt.Errorf("please choose the correct encryption modeWay,only supports CBC ECB CFB OFB CTR")
	}

	var plainText []byte
	switch padding {
	case Pkcs5, Pkcs7:
		plainText = Pkcs7UnPadding(paddingText)
	case Zero:
		plainText = ZeroUnPadding(paddingText)
	case None:
		plainText = paddingText
	case ISO10126:
		plainText = Iso10126UnPadding(paddingText)
	case AnsiX923:
		plainText = AnsiX923UnPadding(paddingText)
	default:
		return nil, fmt.Errorf("please choose the correct paddingWay way,only supports Pkcs5 Pkcs7 Zero None ISO10126 AnsiX923")
	}

	return plainText, nil
}
