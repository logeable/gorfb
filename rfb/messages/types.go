package messages

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type U8 uint8
type U16 uint16
type U32 uint32
type S32 int32

type PixelFormat struct {
	BitsPerPixel  U8
	Depth         U8
	BigEndianFlag U8
	TrueColorFlag U8
	RedMax        U16
	GreenMax      U16
	BlueMax       U16
	RedShift      U8
	GreenShift    U8
	BlueShift     U8
	_             U8
	_             U8
	_             U8
}

func (pf *PixelFormat) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	err := binary.Write(&buf, binary.BigEndian, pf)
	return buf.Bytes(), err
}

func (pf *PixelFormat) MustSerialize() []byte {
	bs, err := pf.Serialize()
	if err != nil {
		panic(fmt.Errorf("PixelFormat serial failed: %+v", pf))
	}
	return bs
}

func (pf *PixelFormat) Deserialize(data []byte) error {
	r := bytes.NewReader(data)
	return binary.Read(r, binary.BigEndian, pf)
}

func (pf *PixelFormat) MustDeserialize(data []byte) {
	err := pf.Deserialize(data)
	if err != nil {
		panic(fmt.Errorf("PixelFormat deserialize failed: %v", data))
	}
}
