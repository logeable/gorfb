package messages

import "io"

type Msg interface {
	Serialize(w io.Writer) error
	Deserialize(r io.Reader) error
	MustSerialize(w io.Writer)
	MustDeserialize(r io.Reader)
}
