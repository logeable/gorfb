package messages

type ClientMessageType uint8

// client message types
const (
	CMTSetPixelFormat ClientMessageType = iota
	_
	CMTSetEncodings
	CMTFramebufferUpdateRequest
	CMTKeyEvent
	CMTPointerEvent
	CMTClientCutText
)

// client memssage types text
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

// translate function
func TranslateClientMessageType(t ClientMessageType) string {
	r, ok := clientMessageTypeText[t]
	if ok {
		return r
	}
	return "Unknown ClientMessageType"
}

// client message type: SetPixelFormat
type CMSetPixelFormat struct {
	// 0
	Type        U8
	_           U8
	_           U8
	_           U8
	PixelFormat PixelFormat
}

type Encoding S32

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

// client message type: SetPixelFormat
type CMSetEncodings struct {
	// 2
	Type              U8
	_                 U8
	NumberOfEncodings U16
	Encodings         Encodings
}

// client message type: FramebufferUpdateRequest
type CMFramebufferUpdateRequest struct {
	// 3
	Type        U8
	Incremental U8
	XPosition   U16
	YPosition   U16
	Width       U16
	Height      U16
}
