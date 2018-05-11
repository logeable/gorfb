package messages

import (
	"fmt"
	"io"

	"github.com/logeable/gorfb/utils"
)

// client message types
const (
	CMTSetPixelFormat uint8 = iota
	_
	CMTSetEncodings
	CMTFramebufferUpdateRequest
	CMTKeyEvent
	CMTPointerEvent
	CMTClientCutText
)

// client memssage types text
var (
	clientMsgTypeText = map[uint8]string{
		CMTSetPixelFormat:           "SetPixelFormat",
		CMTSetEncodings:             "SetEncodings",
		CMTFramebufferUpdateRequest: "FramebufferUpdateRequest",
		CMTKeyEvent:                 "KeyEvent",
		CMTPointerEvent:             "PointerEvent",
		CMTClientCutText:            "ClientCutText",
	}
)

// translate function
func TranslateClientMessageType(t uint8) string {
	r, ok := clientMsgTypeText[t]
	if ok {
		return r
	}
	return "Unknown ClientMsgType"
}

// client message type: SetPixelFormat
type CMSetPixelFormat struct {
	// 0
	Type        uint8
	_           Pad3
	PixelFormat PixelFormat
}

// client message type: SetPixelFormat
type CMSetEncodings struct {
	// 2
	Type      uint8
	Pad       Pad1
	Number    uint16
	Encodings Encodings
}

func (m *CMSetEncodings) Deserialize(r io.Reader) error {
	err := utils.BRead(r, &m.Type, &m.Pad, &m.Number)
	if err != nil {
		return err
	}
	m.Encodings = make(Encodings, m.Number)
	return utils.BRead(r, m.Encodings)
}

func (m *CMSetEncodings) MustDeserialize(r io.Reader) {
	if err := m.Deserialize(r); err != nil {
		panic(fmt.Errorf("deserialize SetEncodings failed: %s", err))
	}
}

// client message type: FramebufferUpdateRequest
type CMFramebufferUpdateRequest struct {
	// 3
	Type        uint8
	Incremental uint8
	X           uint16
	Y           uint16
	Width       uint16
	Height      uint16
}

// client message type: KeyEvent
type CMKeyEvent struct {
	// 4
	Type uint8
	Down uint8
	_    Pad2
	Key  uint32
}

// client message type: PointerEvent
type CMPointerEvent struct {
	// 5
	Type       uint8
	ButtonMask uint8
	X          uint16
	Y          uint16
}

// client message type: ClientCutText
type CMClientCutText struct {
	// 6
	Type   uint8
	Pad    Pad3
	Length uint32
	Text   []uint8
}

func (m *CMClientCutText) Deserialize(r io.Reader) error {
	err := utils.BRead(r, &m.Type, &m.Pad, &m.Length)
	if err != nil {
		return err
	}
	m.Text = make([]uint8, m.Length)
	return utils.BRead(r, m.Text)
}

func (m *CMClientCutText) MustDeserialize(r io.Reader) {
	if err := m.Deserialize(r); err != nil {
		panic(fmt.Errorf("deserialize ClientCutText failed: %s", err))
	}
}
