package messages

import (
	"bytes"
	"encoding/binary"
)

type KeyEvent struct {
	DownFlag uint8
	Padding  [2]uint8
	Key      uint32
}

func NewKeyEvent(data []byte) (*KeyEvent, error) {
	ke := &KeyEvent{}
	r := bytes.NewReader(data)
	err := binary.Read(r, binary.BigEndian, ke)
	return ke, err
}
