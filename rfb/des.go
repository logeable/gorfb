package rfb

import (
	"crypto/des"
)

func DesEncrypt(key []byte, origin []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 16)
	block.Encrypt(buf[:8], origin[:8])
	block.Encrypt(buf[8:], origin[8:])
	return buf, nil
}

func ReverseBits(b byte) byte {
	var d byte
	for i := 0; i < 8; i++ {
		d <<= 1
		d |= b & 1
		b >>= 1
	}
	return d
}
