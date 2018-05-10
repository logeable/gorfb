package rfb

import (
	"bytes"
	"encoding/binary"
	"unsafe"
)

type SecurityType byte

/*
	+--------+--------------------+
	| Number | Name               |
	+--------+--------------------+
	| 0      | Invalid            |
	| 1      | None               |
	| 2      | VNC Authentication |
	+--------+--------------------+
*/
const (
	stInvalid SecurityType = iota
	stNone
	stVNCAuthentication
)

type SecurityTypeResult uint32

/*
	+--------------+--------------+-------------+
	| No. of bytes | Type [Value] | Description |
	+--------------+--------------+-------------+
	| 4            | U32          | status:     |
	|              | 0            | OK          |
	|              | 1            | failed      |
	+--------------+--------------+-------------+
*/
const (
	strOk SecurityTypeResult = iota
	strFailed
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
	bufSize := unsafe.Sizeof(*pf)
	buf := bytes.NewBuffer(make([]byte, bufSize))

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

type ServerInitMessage struct {
	Width, Height     uint16
	ServerPixelFormat *PixelFormat
	NameLength        uint32
	Name              []byte
}

func (msg *ServerInitMessage) Bytes() []byte {
	bufSize := unsafe.Sizeof(*msg)
	buf := bytes.NewBuffer(make([]byte, bufSize))

	binary.Write(buf, binary.BigEndian, msg.Width)
	binary.Write(buf, binary.BigEndian, msg.Height)
	binary.Write(buf, binary.BigEndian, msg.ServerPixelFormat.Bytes())
	binary.Write(buf, binary.BigEndian, msg.NameLength)
	binary.Write(buf, binary.BigEndian, msg.Name)

	return buf.Bytes()
}
