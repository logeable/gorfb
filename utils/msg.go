package utils

import (
	"encoding/binary"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
)

type Serializable interface {
	Serialize(w io.Writer) error
	MustSerialize(w io.Writer)
}

type Deserializable interface {
	Deserialize(r io.Reader) error
	MustDeserialize(r io.Reader)
}

func BWrite(w io.Writer, d ...interface{}) error {
	var err error
	for _, x := range d {
		if msg, ok := x.(Serializable); ok {
			err = msg.Serialize(w)
		} else {
			err = binary.Write(w, binary.BigEndian, x)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func MustBWrite(w io.Writer, d ...interface{}) {
	if err := BWrite(w, d...); err != nil {
		_, file, line, _ := runtime.Caller(1)
		panic(fmt.Errorf("write failed %s:%d %s", filepath.Base(file), line, err))
	}
}

func BRead(r io.Reader, d ...interface{}) error {
	var err error
	for _, x := range d {
		if msg, ok := x.(Deserializable); ok {
			err = msg.Deserialize(r)
		} else {
			err = binary.Read(r, binary.BigEndian, x)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func MustBRead(r io.Reader, d ...interface{}) {
	if err := BRead(r, d...); err != nil {
		_, file, line, _ := runtime.Caller(1)
		panic(fmt.Errorf("read failed %s:%d  %s", filepath.Base(file), line, err))
	}
}
