package types

type ClientMessageType uint8

const (
	CMTSetPixelFormat ClientMessageType = iota
	_
	CMTSetEncodings
	CMTFramebufferUpdateRequest
	CMTKeyEvent
	CMTPointerEvent
	CMTClientCutText
)

var (
	clientMessageTypeText = map[ClientMessageType]string{
		CMTSetPixelFormat:           "SetPixelFormat",
		CMTSetEncodings:             "SetEncodings",
		CMTFramebufferUpdateRequest: "FramebufferUpdateRequest",
		CMTKeyEvent:                 "KeyEvent",
		CMTPointerEvent:             "PointerEvent",
		CMTClientCutText:            "ClientCutText",
	}
)

func TranslateClientMessageType(t ClientMessageType) string {
	r, ok := clientMessageTypeText[t]
	if ok {
		return r
	}
	return "Unknown ClientMessageType"
}
