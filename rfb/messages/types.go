package messages

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Pad1 uint8
type Pad2 uint16
type Pad3 [3]uint8

type PixelFormat struct {
	BitsPerPixel uint8
	Depth        uint8
	BigEndian    uint8
	TrueColor    uint8
	RedMax       uint16
	GreenMax     uint16
	BlueMax      uint16
	RedShift     uint8
	GreenShift   uint8
	BlueShift    uint8
	_            Pad3
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

type Encoding int32

// encoding types
const (
	ENCRaw Encoding = iota
	ENCCopyRect
	ENCRRE
	ENCHextile           = 5
	ENCTRLE              = 15
	ENCZRLE              = 16
	ENCCursorPseudo      = -239
	ENCDesktopSizePseudo = -223
)

type Encodings []Encoding

type Rectangle struct {
	X        uint16
	Y        uint16
	Width    uint16
	Height   uint16
	Encoding Encoding
}

type Rectangles []Rectangle

type RGBMapColor struct {
	Red   uint16
	Green uint16
	Blue  uint16
}

type RGBMapColors []RGBMapColor

type TextMsg struct {
	Length uint32
	Text   []uint8
}
