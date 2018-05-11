package messages

type ClientInitMsg struct {
	Shared uint8
}

type ServerInitMsg struct {
	Width, Height     uint16
	ServerPixelFormat PixelFormat
	NameLength        uint32
	Name              []byte
}
