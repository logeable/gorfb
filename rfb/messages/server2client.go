package messages

type FrameBufferUpdate struct {
	Type    uint8
	Padding [1]uint8
}
