package utils

import (
	"encoding/binary"
	"fmt"
	"io"
	"runtime"
)

func BWrite(w io.Writer, d ...interface{}) error {
	var err error
	for _, x := range d {
		if err = binary.Write(w, binary.BigEndian, x); err != nil {
			return err
		}
	}
	return nil
}

func MustBWrite(w io.Writer, d ...interface{}) {
	if err := BWrite(w, d); err != nil {
		_, file, line, _ := runtime.Caller(1)
		panic(fmt.Errorf("write failed <%s, %d>: %s", file, line, err))
	}
}

func BRead(r io.Reader, d ...interface{}) error {
	var err error
	for _, x := range d {
		if err = binary.Read(r, binary.BigEndian, x); err != nil {
			return err
		}
	}
	return nil
}

func MustBRead(r io.Reader, d ...interface{}) {
	if err := BRead(r, d); err != nil {
		_, file, line, _ := runtime.Caller(1)
		panic(fmt.Errorf("read failed <%s, %d>: %s", file, line, err))
	}
}
