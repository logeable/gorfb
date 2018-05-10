package types

import (
	"bytes"
	"encoding/binary"
)

type PixelFormat struct {
	BitsPerPixel  uint8
	Depth         uint8
	BigEndianFlag uint8
	TrueColorFlag uint8
	RedMax        uint16
	GreenMax      uint16
	BlueMax       uint16
	RedShift      uint8
	GreenShift    uint8
	BlueShift     uint8
	Padding       [3]byte
}

func (pf *PixelFormat) Bytes() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 16))

	binary.Write(buf, binary.BigEndian, pf.BitsPerPixel)
	binary.Write(buf, binary.BigEndian, pf.Depth)
	binary.Write(buf, binary.BigEndian, pf.BigEndianFlag)
	binary.Write(buf, binary.BigEndian, pf.TrueColorFlag)
	binary.Write(buf, binary.BigEndian, pf.RedMax)
	binary.Write(buf, binary.BigEndian, pf.GreenMax)
	binary.Write(buf, binary.BigEndian, pf.BlueMax)
	binary.Write(buf, binary.BigEndian, pf.RedShift)
	binary.Write(buf, binary.BigEndian, pf.GreenShift)
	binary.Write(buf, binary.BigEndian, pf.BlueShift)
	binary.Write(buf, binary.BigEndian, pf.Padding)

	return buf.Bytes()
}

func NewPixelFormat(data []byte) (*PixelFormat, error) {
	pf := &PixelFormat{}
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.BigEndian, pf)
	return pf, err
}
