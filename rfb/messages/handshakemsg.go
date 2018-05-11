package messages

import (
	"crypto/rand"
	"fmt"
	"io"
)

const (
	ProtocolVersionFormat = "RFB %03d.%03d\n"
)

// protocol version info
type HMProtocolVersion struct {
	Major int
	Minor int
}

func (m *HMProtocolVersion) MustSerialize(w io.Writer) {
	if err := m.Serialize(w); err != nil {
		panic(fmt.Errorf("serialize HMProtocolVersion failed: %s", err))
	}
}

func (m *HMProtocolVersion) MustDeserialize(r io.Reader) {
	if err := m.Deserialize(r); err != nil {
		panic(fmt.Errorf("deserialize HMProtocolVersion failed: %s", err))
	}
}

func (m *HMProtocolVersion) Serialize(w io.Writer) error {
	_, err := fmt.Fprintf(w, ProtocolVersionFormat, m.Major, m.Minor)
	return err
}

func (m *HMProtocolVersion) Deserialize(r io.Reader) error {
	_, err := fmt.Fscanf(r, ProtocolVersionFormat, &m.Major, &m.Minor)
	return err
}

type HMSecurityType struct {
	Number        uint8
	SecurityTypes SecurityTypes
}

type SecurityTypes []uint8

type HMClientSecurityType uint8

/*
	+--------+--------------------+
	| Number | Name               |
	+--------+--------------------+
	| 0      | Invalid            |
	| 1      | None               |
	| 2      | VNC Authentication |
	+--------+--------------------+
*/
const (
	STInvalid uint8 = iota
	STNone
	STVNCAuthentication
)

/*
	+--------------+--------------+-------------+
	| No. of bytes | Type [Value] | Description |
	+--------------+--------------+-------------+
	| 4            | U32          | status:     |
	|              | 0            | OK          |
	|              | 1            | failed      |
	+--------------+--------------+-------------+
*/
const (
	STROk uint32 = iota
	STRFailed
)

type HMSecurityResult struct {
	Status uint32
}

type VNCAuthChallenge [2]uint8

func NewVNCAuthChallengeMsg() *VNCAuthChallenge {
	msg := &VNCAuthChallenge{}
	_, err := rand.Read(msg[:])
	if err != nil {
		panic(fmt.Errorf("generate VNC authentication challenge failed: %s", err))
	}
	return msg
}

type VNCAuthResponseMsg struct {
	Response [2]uint8
}
