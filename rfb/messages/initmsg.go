package messages

import (
	"io"

	"fmt"

	"github.com/logeable/gorfb/utils"
)

type ClientInitMsg struct {
	Shared uint8
}

type ServerInitMsg struct {
	Width, Height     uint16
	ServerPixelFormat PixelFormat
	NameLength        uint32
	Name              []byte
}

func (m *ServerInitMsg) Serialize(w io.Writer) error {
	return utils.BWrite(w, m.Width, m.Height, m.ServerPixelFormat, m.NameLength, m.Name)
}

func (m *ServerInitMsg) MustSerialize(w io.Writer) {
	if err := m.Serialize(w); err != nil {
		panic(fmt.Errorf("serialize ServerInitMsg failed: %s", err))
	}
}
