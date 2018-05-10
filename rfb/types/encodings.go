package types

type Encoding int32

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