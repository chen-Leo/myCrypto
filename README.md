# chen-Leo/myCrypto.git

Some encryption algorithm encapsulation in go language makes it more convenient
to use

aes
* support 128 192 256 bits key
* support CBC ECB CFB OFB CTR modes of operation
* support Pkcs5 Pkcs7 Zero None ISO10126 AnsiX923 padding way (chose None,the
  input text must be a multiple of block size)
* IV length must equal block size 16 bytes (ECB, IV is unnecessary)

```go
package main

import (
  "encoding/base64"
  "fmt"
  mycrypto "github.com/chen-Leo/mycrypto"
)

func main() {
  var plainText = []byte("hello_world")
  var key = []byte("h8FpJvUZ6YIb7Kwq")
  var iv = []byte("1234567890123456")

  ciphertext, err := mycrypto.AesEnc(plainText, key, iv, mycrypto.CBC, mycrypto.Pkcs7)
  if err != nil {
    panic(err)
  }

  fmt.Println("ciphertext(base64):", base64.StdEncoding.EncodeToString(ciphertext))

  result, err := mycrypto.AesDec(ciphertext, key, iv, mycrypto.CBC, mycrypto.Pkcs7)
  if err != nil {
    panic(err)
  }

  fmt.Println("Decrypted result:", string(result))
}
```

```go
var plainText = []byte("hello_world")
var key = []byte("h8FpJvUZ6YIb7Kwq")
var iv = []byte("1234567890123456")

// ECB, IV is unnecessary
ciphertext, err := mycrypto.AesEnc(plainText, key, nil, mycrypto.ECB, mycrypto.AnsiX923)
if err != nil {
panic(err)
}

fmt.Println("ciphertext(base64):", base64.StdEncoding.EncodeToString(ciphertext))

result, err := mycrypto.AesDec(ciphertext, key, nil, mycrypto.ECB, mycrypto.AnsiX923)
if err != nil {
panic(err)
}

fmt.Println("Decrypted result:", string(result))
```

des
* support 56 bits key
* support CBC ECB CFB OFB CTR modes of operation
* support Pkcs5 Pkcs7 Zero None ISO10126 AnsiX923 padding way (chose None,the
  input text must be a multiple of block size)
* IV length must equal block size 8 bytes (ECB, IV is unnecessary)
```go
package main

import (
  "encoding/base64"
  "fmt"
  mycrypto "github.com/chen-Leo/mycrypto"
)

func main() {
  var plainText = []byte("hello_world")
  var key = []byte("h8FpJvUZ")
  var iv = []byte("12345678")

  ciphertext, err := mycrypto.DesEnc(plainText, key, iv, mycrypto.CBC, mycrypto.Pkcs7)
  if err != nil {
    panic(err)
  }

  fmt.Println("ciphertext(base64):", base64.StdEncoding.EncodeToString(ciphertext))

  result, err := mycrypto.DesDec(ciphertext, key, iv, mycrypto.CBC, mycrypto.Pkcs7)
  if err != nil {
    panic(err)
  }

  fmt.Println("Decrypted result:", string(result))
}
```

```go
var plainText = []byte("hello_world")
var key = []byte("h8FpJvUZ")
var iv = []byte("12345678")

// ECB, IV is unnecessary
ciphertext, err := mycrypto.DesEnc(plainText, key, nil, mycrypto.ECB, mycrypto.AnsiX923)
if err != nil {
panic(err)
}

fmt.Println("ciphertext(base64):", base64.StdEncoding.EncodeToString(ciphertext))

result, err := mycrypto.DesDec(ciphertext, key, nil, mycrypto.ECB, mycrypto.AnsiX923)
if err != nil {
panic(err)
}

fmt.Println("Decrypted result:", string(result))
```