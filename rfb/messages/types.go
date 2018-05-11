package messages

import (
	"fmt"
	"io"

	"github.com/logeable/gorfb/utils"
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

type Encoding int32

// encoding types
const (
	ENCRaw int32 = iota
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

func (m *TextMsg) Serialize(w io.Writer) error {
	return utils.BWrite(w, m.Length, m.Text)
}

func (m *TextMsg) MustSerialize(w io.Writer) {
	if err := m.Serialize(w); err != nil {
		panic(fmt.Errorf("serialize TextMsg failed: %s", err))
	}
}
