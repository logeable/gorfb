package messages

type ClientMsgType uint8

// client message types
const (
	CMTSetPixelFormat ClientMsgType = iota
	_
	CMTSetEncodings
	CMTFramebufferUpdateRequest
	CMTKeyEvent
	CMTPointerEvent
	CMTClientCutText
)

// client memssage types text
var (
	clientMsgTypeText = map[ClientMsgType]string{
		CMTSetPixelFormat:           "SetPixelFormat",
		CMTSetEncodings:             "SetEncodings",
		CMTFramebufferUpdateRequest: "FramebufferUpdateRequest",
		CMTKeyEvent:                 "KeyEvent",
		CMTPointerEvent:             "PointerEvent",
		CMTClientCutText:            "ClientCutText",
	}
)

// translate function
func TranslateClientMessageType(t ClientMsgType) string {
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
	_         Pad1
	Number    uint16
	Encodings Encodings
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
	_      Pad3
	Length uint32
	Text   uint8
}
