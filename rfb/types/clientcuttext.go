package types

import (
	"bytes"
	"encoding/binary"
)

type ClientCutText struct {
	Padding [3]uint8
	Length  uint32
	Text    []uint8
}

func NewClientCutText(data []byte) (*ClientCutText, error) {
	cct := &ClientCutText{}
	r := bytes.NewReader(data)
	err := binary.Read(r, binary.BigEndian, cct)
	return cct, err
}
