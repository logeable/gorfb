package rfb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os/user"
	"path/filepath"

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
}

func (s *Session) Read(p []byte) (n int, err error) {
	return s.conn.Read(p)
}

func (s *Session) ReadFull(buf []byte) (int, error) {
	return io.ReadFull(s.conn, buf)
}

func (s *Session) ReadUint8() (uint8, error) {
	var r uint8
	err := binary.Read(s.conn, binary.BigEndian, &r)
	return r, err
}

func (s *Session) ReadUint16() (uint16, error) {
	var r uint16
	err := binary.Read(s.conn, binary.BigEndian, &r)
	return r, err
}

func (s *Session) ReadUint32() (uint32, error) {
	var r uint32
	err := binary.Read(s.conn, binary.BigEndian, &r)
	return r, err
}

func (s *Session) ReadInt32() (int32, error) {
	var r int32
	err := binary.Read(s.conn, binary.BigEndian, &r)
	return r, err
}

func (s *Session) SkipBytes(n int) error {
	buf := make([]byte, n)
	_, err := io.ReadFull(s.conn, buf)
	return err
}

func (s *Session) Write(buf []byte) (int, error) {
	return s.conn.Write(buf)
}

func (s *Session) WriteString(str string) (int, error) {
	return s.conn.Write([]byte(str))
}

func (s *Session) WriteUint8(u uint8) error {
	return binary.Write(s.conn, binary.BigEndian, u)
}

func (s *Session) WriteUint16(u uint16) error {
	return binary.Write(s.conn, binary.BigEndian, u)
}

func (s *Session) WriteUint32(u uint32) error {
	return binary.Write(s.conn, binary.BigEndian, u)
}

func (s *Session) Handshake() {
	s.protocolVersionHandshake()
	s.securityHandshake()
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

func (s *Session) securityHandshake() {

	avaliableSt := s.server.securityTypes
	st := &messages.HMSecurityType{
		Number:        uint8(len(avaliableSt)),
		SecurityTypes: avaliableSt,
	}
	if st.Number == 0 {
		reason := "the server cannot support the desired protocol version"
		reasonMsg := messages.TextMsg{
			Length: uint32(len(reason)),
			Text:   []uint8(reason),
		}
		utils.BWrite(s, reasonMsg)
		panic(fmt.Errorf(reason))
	}
	utils.BWrite(s, st)

	var cst messages.HMClientSecurityType
	utils.MustBRead(s, &cst)

	err := s.authenticate(uint8(cst))

	if err != nil {
		sr := messages.HMSecurityResult{Status: messages.STRFailed}
		utils.MustBWrite(s, sr)
		reason := "invalid passwd"
		msg := messages.TextMsg{Length: uint32(len(reason)), Text: []uint8(reason)}
		utils.MustBWrite(s, msg)
	} else {
		sr := messages.HMSecurityResult{Status: messages.STROk}
		utils.MustBWrite(s, sr)
	}
}

func (s *Session) authenticate(t uint8) error {
	switch t {
	case messages.STNone:
		log.Println("auth method: none")
	case messages.STVNCAuthentication:
		authChallenge := messages.NewVNCAuthChallengeMsg()
		utils.MustBWrite(s, authChallenge)
		authResp := &messages.VNCAuthResponseMsg{}
		utils.MustBRead(s, authResp)
		if !checkCredential([2]uint8(*authChallenge), authResp.Response) {
			return fmt.Errorf("invalid passwd")
		}
	default:
		panic(fmt.Errorf("invalid security type: %d", t))
	}
	return nil
}

func checkCredential(challenge, response [2]byte) bool {
	passwd := readServerPasswd()

	keyBuf := make([]byte, 8)
	for i := 0; i < len(passwd); i++ {
		// https://www.vidarholen.net/contents/junk/vnc.html
		keyBuf[i] = ReverseBits(passwd[i])
	}

	encrypted, err := DesEncrypt(keyBuf, challenge[:])
	if err != nil {
		panic(fmt.Errorf("des encrypt failed: %s", err))
	}
	return bytes.Equal(response[:], encrypted)
}

func readServerPasswd() []byte {
	u, err := user.Current()
	if err != nil {
		panic(fmt.Errorf("get current use info failed: %s", err))
	}
	p := filepath.Join(u.HomeDir, passwdFile)
	passwd, err := ioutil.ReadFile(p)
	if err != nil {
		panic(fmt.Errorf("read passwd file failed: %s", err))
	}
	return bytes.TrimSpace(passwd)
}

func (s *Session) Initialization() {
	s.clientInit()
	s.serverInit()
}

func (s *Session) clientInit() {
	buf := make([]byte, 1)
	_, err := s.ReadFull(buf)
	if err != nil {
		panic(fmt.Errorf("read client init message failed: %s", err))
	}
	log.Printf("<<< read client init message: %v", buf)
	// if shared flag is zero, disconnect all other connections
	s.shared = buf[0]
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
	sim := &messages.ServerInitMsg{
		Width:             s.Server().Width,
		Height:            s.Server().Height,
		ServerPixelFormat: *s.Server().defaultPF,
		NameLength:        uint32(len(s.Server().Name)),
		Name:              []byte(s.Server().Name),
	}
	simBytes := sim.Bytes()
	_, err := s.Write(simBytes)
	if err != nil {
		panic(fmt.Errorf("send server init message failed: %v", err))
	}
	log.Printf(">>> send server init message: %v", simBytes)
}

func (s *Session) ProcessNormalProtocol() {

	for {
		u8, err := s.ReadUint8()
		if err != nil {
			panic(fmt.Errorf("read client message type failed: %s", err))
		}

		cmt := messages.ClientMsgType(u8)
		log.Printf("<<< read client message type: %d <%s>", u8, messages.TranslateClientMessageType(cmt))

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
}

func (s *Session) serverPixelFormat() *messages.PixelFormat {
	return s.server.defaultPF
}

func (s *Session) setServerPixelFormat(pf *messages.PixelFormat) {
	s.server.defaultPF = pf
}

func (s *Session) setPixelFormat() {
	log.Println("handle SetPixelFormat")
	const paddingLen = 3
	err := s.SkipBytes(paddingLen)
	if err != nil {
		panic(fmt.Errorf("skip padding failed: %s", err))
	}

	buf := make([]byte, 16)
	_, err = s.ReadFull(buf)
	if err != nil {
		panic(fmt.Errorf("read pixel format failed: %s", err))
	}
	pf, err := messages.NewPixelFormat(buf)
	if err != nil {
		panic(fmt.Errorf("new pixel format failed: %s", err))
	}
	s.setServerPixelFormat(pf)
	log.Printf(">>> read pixel format: %v, %+v", buf, pf)

	if pf.TrueColorFlag == 0 {
		s.setColorMapEntries()
	}
}

func (s *Session) setServerEncodings(encodings messages.Encodings) {
	s.server.encodings = encodings
}

func (s *Session) serverEncodings() messages.Encodings {
	return s.server.encodings
}

func (s *Session) setEncodings() {
	log.Println("handle setEncodings")
	err := s.SkipBytes(1)
	if err != nil {
		panic(fmt.Errorf("skip padding failed :%s", err))
	}

	encLen, err := s.ReadUint16()
	if err != nil {
		panic(fmt.Errorf("read number of encodings failed: %s", err))
	}
	log.Printf("<<< read number of encodings: %d", encLen)

	encodings := make(messages.Encodings, encLen)
	for i := uint16(0); i < encLen; i++ {
		enc, err := s.ReadInt32()
		if err != nil {
			panic(fmt.Errorf("read encodings failed: %s", err))
		}
		encodings[i] = messages.Encoding(enc)
	}
	s.setServerEncodings(encodings)
	log.Printf("<<< read encodings: %v", encodings)
}

func (s *Session) framebufferUpdateRequest() {
	log.Println("handle framebufferUpdateRequest")
	buf := make([]byte, 9)
	_, err := s.ReadFull(buf)
	if err != nil {
		panic(fmt.Errorf("read framebuffer update request failed: %s", err))
	}

	fbur, err := messages.NewFramebufferUpdateRequest(buf)
	if err != nil {
		panic(fmt.Errorf("new framebuffer update request failed: %s", err))
	}
	log.Printf(">>> read framebuffer update request: %v, %+v", buf, fbur)
}

func (s *Session) keyEvent() {
	log.Println("handle keyEvent")
	buf := make([]byte, 7)
	_, err := s.ReadFull(buf)
	if err != nil {
		panic(fmt.Errorf("read key event failed: %s", err))
	}

	ke, err := messages.NewKeyEvent(buf)
	if err != nil {
		panic(fmt.Errorf("new key event failed: %s", err))
	}
	log.Printf(">>> read key event: %v, %+v", buf, ke)
	err = s.WriteUint8(2)
	if err != nil {
		panic(err)
	}
}

func (s *Session) pointerEvent() {
	log.Println("handle pointerEvent")
	buf := make([]byte, 5)
	_, err := s.ReadFull(buf)
	if err != nil {
		panic(fmt.Errorf("read pointer event failed: %s", err))
	}
	pe, err := messages.NewPointerEvent(buf)
	if err != nil {
		panic(fmt.Errorf("new pointer event failed: %s", err))
	}
	log.Printf("<<< read pointer event: %v, %+v", buf, pe)
}

func (s *Session) clientCutText() {
	log.Println("handle clientCutText")
	err := s.SkipBytes(3)
	if err != nil {
		panic(fmt.Errorf("skip padding failed: %s", err))
	}
	l, err := s.ReadUint32()
	if err != nil {
		panic(fmt.Errorf("read clientcut text length failed: %s", err))
	}

	buf := make([]byte, l)
	_, err = s.ReadFull(buf)
	if err != nil {
		panic(fmt.Errorf("read clientcut text failed: %s", err))
	}

	log.Printf(">>> read clientcut text: %v, %s", buf, buf)
}

func (s *Session) setColorMapEntries() {
	// todo: implement setColorMapEntries
	panic("not implemented")
}
