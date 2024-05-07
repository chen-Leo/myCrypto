package crypto

import (
	"strings"
	"testing"
)

func TestShortDesDecEnc(t *testing.T) {
	var plainText = []byte("hello_world")

	var keyMap = map[string][]byte{
		"key64": []byte("h8FpJvUZ"),
	}
	var iv = []byte("6YIb7Kwq")

	var modes = []modeWay{CBC, ECB, CFB, OFB, CTR}
	// without NoPadding because the input text must be a multiple of block size
	var paddings = []paddingWay{Pkcs5, Pkcs7, Zero, ISO10126, AnsiX923}

	for _, mode := range modes {
		for _, way := range paddings {
			for keyName, keys := range keyMap {
				//t.Logf("----------------testing [%v] bit Key [%v] [%v]----------------------", keyName, mode, way)
				ciphertext, err := DesEnc(plainText, keys, iv, mode, way)
				if err != nil {
					t.Errorf("[%v] bit Key [%v] [%v] encryption error:[%v]", keyName, mode, way, err)
					return
				}

				//t.Logf("[%v] bit Key [%v] [%v] ciphertext(base64):[%v]", keyName, mode, way, base64.StdEncoding.EncodeToString(ciphertext))

				result, err := DesDec(ciphertext, keys, iv, mode, way)
				if err != nil {
					t.Errorf("[%v]  bit Key [%v] [%v] encryption error:[%v]", keyName, mode, way, err)
					return
				}

				if string(result) != string(plainText) {
					t.Errorf("[%v]  bit Key [%v] [%v] No Passing", keyName, mode, way)
				}
				//
				//	//t.Logf("[%v] bit Key [%v] [%v] PASS!!", keyName, mode, way)
				//
			}
		}
	}
}

func TestLongDesDecEnc(t *testing.T) {
	var plainText = []byte("Jh2Ls9Fg8Kp6Dq1Zx4Vc7Bn0Mw3Nr5Tt8Yu1Ii4Op7Ah9Gj2Fk5Ll8Jh2Ls9Fg8" +
		"Kp6Dq1Zx4Vc7Bn0Mw3Nr5Tt8Yu1Ii4Op7Ah9Gj2Fk5Ll8Jh2Ls9Fg8Kp6Dq1Zx4Vc7Bn0Mw3Nr5Tt8Y" +
		"u1Ii4Op7Ah9Gj2Fk5Ll8Jh2Ls9Fg8Kp6Dq1Zx4Vc7Bn0Mw3Nr5Tt8Yu1Ii4Op7Ah9Gj2Fk5Ll8Jh2Ls" +
		"9Fg8Kp6Dq1Zx4Vc7Bn0Mw3Nr5Tt8Yu1Ii4Op7Ah9Gj2Fk5Ll8Jh2Ls9Fg8Kp6Dq1Zx4Vc7Bn0Mw3Nr5T" +
		"t8Yu1Ii4Op7Ah9Gj2Fk5Ll8")

	var keyMap = map[string][]byte{
		"key64": []byte("h8FpJvUZ"),
	}
	var iv = []byte("6YIb7Kwq")

	var modes = []modeWay{CBC, ECB, CFB, OFB, CTR}
	// without NoPadding because the input text must be a multiple of block size
	var paddings = []paddingWay{Pkcs5, Pkcs7, Zero, ISO10126, AnsiX923}

	for _, mode := range modes {
		for _, way := range paddings {
			for keyName, keys := range keyMap {
				//t.Logf("----------------testing [%v] bit Key [%v] [%v]----------------------", keyName, mode, way)
				ciphertext, err := DesEnc(plainText, keys, iv, mode, way)
				if err != nil {
					t.Errorf("[%v] bit Key [%v] [%v] encryption error:[%v]", keyName, mode, way, err)
					return
				}

				//t.Logf("[%v] bit Key [%v] [%v] ciphertext(base64):[%v]", keyName, mode, way, base64.StdEncoding.EncodeToString(ciphertext))

				result, err := DesDec(ciphertext, keys, iv, mode, way)
				if err != nil {
					t.Errorf("[%v]  bit Key [%v] [%v] encryption error:[%v]", keyName, mode, way, err)
					return
				}

				if string(result) != string(plainText) {
					t.Errorf("[%v]  bit Key [%v] [%v] No Passing", keyName, mode, way)
				}
				//
				//	//t.Logf("[%v] bit Key [%v] [%v] PASS!!", keyName, mode, way)
				//
			}
		}
	}
}

func TestNoPaddingDesDecEnc(t *testing.T) {
	var short8PlainText = []byte("eF8Kp6Dq")
	var long8PlainText = []byte("h8FpJvUZ6YIb7KwqeF8Kp6Dq1Zx4Vc7Bh8FpJvUZ6YIb7KwqeF8Kp6Dq1Zx4Vc7Bh8FpJvUZ6YIb7KwqeF8Kp6Dq1Zx4Vc7Bh8FpJvUZ6YIb7KwqeF8Kp6Dq1Zx4Vc7Bh8FpJvUZ6YIb7Kwq")

	var keyMap = map[string][]byte{
		"key64": []byte("h8FpJvUZ"),
	}
	var iv = []byte("6YIb7Kwq")

	var modes = []modeWay{CBC, ECB, CFB, OFB, CTR}

	for _, mode := range modes {
		for keyName, keys := range keyMap {
			//t.Logf("----------------testing [%v] bit Key [%v] [%v]----------------------", keyName, mode, way)
			ciphertext, err := DesEnc(short8PlainText, keys, iv, mode, None)
			if err != nil {
				t.Errorf("[%v] bit Key [%v] [%v] encryption error:[%v]", keyName, mode, None, err)
				return
			}

			//t.Logf("[%v] bit Key [%v] [%v] ciphertext(base64):[%v]", keyName, mode, way, base64.StdEncoding.EncodeToString(ciphertext))

			result, err := DesDec(ciphertext, keys, iv, mode, None)
			if err != nil {
				t.Errorf("[%v]  bit Key [%v] [%v] encryption error:[%v]", keyName, mode, None, err)
				return
			}

			if string(result) != string(short8PlainText) {
				t.Errorf("[%v]  bit Key [%v] [%v] No Passing", keyName, mode, None)
			}
			//
			//	//t.Logf("[%v] bit Key [%v] [%v] PASS!!", keyName, mode, way)
			//

			//-----------------------------------------------------------------------------------------------
			//-----------------------------------------------------------------------------------------------

			ciphertext, err = DesEnc(long8PlainText, keys, iv, mode, None)
			if err != nil {
				t.Errorf("[%v] bit Key [%v] [%v] encryption error:[%v]", keyName, mode, None, err)
				return
			}

			//t.Logf("[%v] bit Key [%v] [%v] ciphertext(base64):[%v]", keyName, mode, way, base64.StdEncoding.EncodeToString(ciphertext))

			result, err = DesDec(ciphertext, keys, iv, mode, None)
			if err != nil {
				t.Errorf("[%v]  bit Key [%v] [%v] encryption error:[%v]", keyName, mode, None, err)
				return
			}

			if string(result) != string(long8PlainText) {
				t.Errorf("[%v]  bit Key [%v] [%v] No Passing", keyName, mode, None)
			}
			//
			//	//t.Logf("[%v] bit Key [%v] [%v] PASS!!", keyName, mode, way)
			//
		}
	}

	// error length test
	var errorLengthPlainText = []byte("hello_world")
	_, err := DesEnc(errorLengthPlainText, keyMap["key64"], iv, CBC, None)
	if err != nil && strings.Contains(err.Error(), "the input text must be a multiple of block size") {
		t.Logf("NoPadding wrong length input PASS: the input text must be a multiple of block size")
	} else {
		t.Errorf("NoPadding wrong length input no PASS")
	}
}
