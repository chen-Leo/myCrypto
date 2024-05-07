package crypto

type paddingWay string

const (
	Pkcs5    paddingWay = "Pkcs5"
	Pkcs7    paddingWay = "Pkcs7"
	Zero     paddingWay = "ZeroPadding"
	None     paddingWay = "NoPadding"
	ISO10126 paddingWay = "ISO10126"
	AnsiX923 paddingWay = "AnsiX923"
)

type modeWay string

const (
	CBC modeWay = "CBC"
	ECB modeWay = "ECB"
	CFB modeWay = "CFB"
	OFB modeWay = "OFB"
	CTR modeWay = "CTR"
)
