package rfb

import (
	"fmt"
	"log"
	"net"

	"bufio"

	"github.com/logeable/gorfb/rfb/messages"
	"github.com/logeable/gorfb/utils"
)

const (
	passwdFile = ".rfbpasswd"
)

var (
	keyErr = fmt.Errorf("key invalid")
)

type Session struct {
	Major, Minor int
	ID           string
	conn         net.Conn
	shared       uint8
	server       *Server
	securityType messages.SecurityType
	bufrw        *bufio.ReadWriter
}

func (s *Session) Read(buf []byte) (n int, err error) {
	return s.bufrw.Read(buf)
}

func (s *Session) Peek(n int) ([]uint8, error) {
	return s.bufrw.Peek(n)
}

func (s *Session) Write(buf []byte) (int, error) {
	defer s.bufrw.Flush()
	return s.bufrw.Write(buf)
}

func (s *Session) Serve() {
	s.Handshake()
	s.Initialization()
	s.ProcessNormalProtocol()
}

/*
>>> RFB xxx.xxx\n
<<< RFB xxx.xxx\n
*/
func (s *Session) protocolVersionHandshake() {
	log.Println("begin: protocol version handshake")
	spv := &messages.HMProtocolVersion{
		Major: s.server.Major,
		Minor: s.server.Minor,
	}
	spv.MustSerialize(s)

	cpv := &messages.HMProtocolVersion{}
	cpv.MustDeserialize(s)

	if cpv.Major != 3 {
		cpv.Major = 3
	}
	if cpv.Minor != 3 && cpv.Minor != 7 && cpv.Minor != 8 {
		cpv.Minor = 3
	}
	log.Println("end: protocol version handshake")
}

func (s *Session) Handshake() {
	s.protocolVersionHandshake()
	s.securityHandshake()
	s.securityResultHandshake()
}

func (s *Session) securityHandshake() {
	availableTypes := s.server.securityTypes
	st := &messages.HMSecurityType{
		Number:        uint8(len(availableTypes)),
		SecurityTypes: availableTypes,
	}
	if st.Number == 0 {
		reason := "the server cannot support the desired protocol version"
		reasonMsg := messages.TextMsg{
			Length: uint32(len(reason)),
			Text:   []uint8(reason),
		}
		reasonMsg.MustSerialize(s)
		panic(fmt.Errorf(reason))
	}
	st.MustSerialize(s)

	var cst messages.HMClientSecurityType
	utils.MustBRead(s, &cst)
	s.securityType = cst.Type
}

func (s *Session) securityResultHandshake() {
	err := s.authenticate(s.securityType)

	if err != nil {
		sr := messages.HMSecurityResult{Status: messages.STRFailed}
		utils.MustBWrite(s, sr)
		reason := "invalid password"
		msg := messages.TextMsg{Length: uint32(len(reason)), Text: []uint8(reason)}
		utils.MustBWrite(s, msg)
	} else {
		sr := messages.HMSecurityResult{Status: messages.STROk}
		utils.MustBWrite(s, sr)
	}
}

func (s *Session) authenticate(t messages.SecurityType) error {
	switch t {
	case messages.STNone:
		log.Println("auth method: none")
	case messages.STVNCAuthentication:
		authChallenge := messages.NewVNCAuthChallengeMsg()
		utils.MustBWrite(s, authChallenge)
		authResp := &messages.HMVNCAuthResponseMsg{}
		utils.MustBRead(s, authResp)
		if !checkCredential(authChallenge.Challenge, authResp.Response) {
			return fmt.Errorf("invalid passwd")
		}
	default:
		panic(fmt.Errorf("invalid security type: %d", t))
	}
	return nil
}

func (s *Session) Initialization() {
	log.Println("begin: Initialization")
	s.clientInit()
	s.serverInit()
	log.Println("end: Initialization")
}

func (s *Session) clientInit() {
	msg := messages.ClientInitMsg{}
	utils.MustBRead(s, &msg)
	// if shared flag is zero, disconnect all other connections
	s.shared = msg.Shared
	if s.shared == 0 {
		log.Println("clean other sessions due to shared flag is zero")
		go s.CleanOtherSessions()
	}
}

func (s *Session) CleanOtherSessions() {
	s.server.CleanSessionExcept(s)
}

func (s *Session) Server() *Server {
	return s.server
}

func (s *Session) serverInit() {
	msg := &messages.ServerInitMsg{
		Width:             s.Server().Width,
		Height:            s.Server().Height,
		ServerPixelFormat: *s.Server().defaultPF,
		NameLength:        uint32(len(s.Server().Name)),
		Name:              []byte(s.Server().Name),
	}
	utils.MustBWrite(s, msg)
}

func (s *Session) ProcessNormalProtocol() {
	log.Println("begin: process normal protocol")
	for {
		cmtBuf, err := s.Peek(1)
		if err != nil {
			panic(fmt.Errorf("read normal protocol type failed: %s", err))
		}
		cmt := cmtBuf[0]

		if err != nil {
			panic(fmt.Errorf("read client message type failed: %s", err))
		}

		log.Printf("<<< read client message type: %d <%s>", cmt, messages.TranslateClientMessageType(cmt))

		switch cmt {
		case messages.CMTSetPixelFormat:
			s.setPixelFormat()
		case messages.CMTSetEncodings:
			s.setEncodings()
		case messages.CMTFramebufferUpdateRequest:
			s.framebufferUpdateRequest()
		case messages.CMTKeyEvent:
			s.keyEvent()
		case messages.CMTPointerEvent:
			s.pointerEvent()
		case messages.CMTClientCutText:
			s.clientCutText()
		default:
			panic(fmt.Errorf("unknown client message type: %d", cmt))
		}
	}
	log.Println("end: process normal protocol")
}

func (s *Session) serverPixelFormat() *messages.PixelFormat {
	return s.server.defaultPF
}

func (s *Session) setServerPixelFormat(pf *messages.PixelFormat) {
	s.server.defaultPF = pf
}

func (s *Session) setPixelFormat() {
	log.Println("handle SetPixelFormat")
	msg := &messages.CMSetPixelFormat{}
	utils.MustBRead(s, msg)
	s.setServerPixelFormat(&msg.PixelFormat)
}

func (s *Session) serverEncodings() messages.Encodings {
	return s.server.encodings
}

func (s *Session) setServerEncodings(encodings messages.Encodings) {
	s.server.encodings = encodings
}

func (s *Session) setEncodings() {
	log.Println("handle setEncodings")
	msg := &messages.CMSetEncodings{}
	utils.MustBRead(s, msg)
	s.setServerEncodings(msg.Encodings)
}

func (s *Session) framebufferUpdateRequest() {
	log.Println("handle framebufferUpdateRequest")
	msg := &messages.CMFramebufferUpdateRequest{}
	utils.MustBRead(s, msg)
}

func (s *Session) keyEvent() {
	log.Println("handle keyEvent")
	msg := &messages.CMKeyEvent{}
	utils.MustBRead(s, msg)
}

func (s *Session) pointerEvent() {
	log.Println("handle pointerEvent")
	msg := &messages.CMPointerEvent{}
	utils.MustBRead(s, msg)
}

func (s *Session) clientCutText() {
	log.Println("handle clientCutText")
	msg := &messages.CMClientCutText{}
	utils.MustBRead(s, msg)
}

func (s *Session) setColorMapEntries() {
	// todo: implement setColorMapEntries
	panic("not implemented")
}
