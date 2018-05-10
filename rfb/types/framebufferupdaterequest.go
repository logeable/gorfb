package types

import (
	"bytes"
	"encoding/binary"
)

type FramebufferUpdateRequest struct {
	Incremental uint8
	XPosition   uint16
	YPosition   uint16
	Width       uint16
	Height      uint16
}

func NewFramebufferUpdateRequest(data []byte) (*FramebufferUpdateRequest, error) {
	fbur := &FramebufferUpdateRequest{}
	r := bytes.NewReader(data)
	err := binary.Read(r, binary.BigEndian, fbur)
	return fbur, err
}
