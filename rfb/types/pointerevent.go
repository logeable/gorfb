package types

import (
	"bytes"
	"encoding/binary"
)

type PointerEvent struct {
	ButtonMask uint8
	XPosition  uint16
	YPosition  uint16
}

func NewPointerEvent(data []byte) (*PointerEvent, error) {
	pe := &PointerEvent{}
	r := bytes.NewReader(data)
	err := binary.Read(r, binary.BigEndian, pe)
	return pe, err
}
