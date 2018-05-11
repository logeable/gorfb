package messages

type ServerMsgType uint8

// server message types
const (
	SMTFramebufferUpdate ServerMsgType = iota
	SMTSetColorMapEntries
	SMTBell
	SMTServerCutText
)

// server message: FrameBufferUpdate
type SMFrameBufferUpdate struct {
	// 0
	Type       uint8
	_          Pad1
	Number     uint16
	Rectangles Rectangles
}

type SMSetColorMapEntries struct {
	// 1
	Type         uint8
	_            Pad1
	FirstColor   uint16
	Number       uint16
	RGBMapColors RGBMapColors
}

type SMBell struct {
	// 2
	Type uint8
}

type SMServerCutText struct {
	// 3
	Type   uint8
	_      Pad3
	Length uint32
	Text   uint8
}
