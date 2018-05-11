package messages

import (
	"bytes"
	"encoding/binary"
)

type ServerInitMessage struct {
	Width, Height     uint16
	ServerPixelFormat PixelFormat
	NameLength        uint32
	Name              []byte
}

func (msg *ServerInitMessage) Bytes() []byte {
	buf := bytes.NewBuffer(make([]byte, 0, 24+msg.NameLength))

	binary.Write(buf, binary.BigEndian, msg.Width)
	binary.Write(buf, binary.BigEndian, msg.Height)
	binary.Write(buf, binary.BigEndian, msg.ServerPixelFormat.Bytes())
	binary.Write(buf, binary.BigEndian, msg.NameLength)
	binary.Write(buf, binary.BigEndian, msg.Name)

	return buf.Bytes()
}
