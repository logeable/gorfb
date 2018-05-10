package rfb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os/user"
	"path/filepath"

	"strings"

	"github.com/logeable/gorfb/rfb/types"
)

const (
	protocolVersionFormat = "RFB %03d.%03d\n"
	passwdFile            = ".rfbpasswd"
)

var (
	keyErr = fmt.Errorf("key invalid")
)

type Session struct {
	Major, Minor int
	securityType types.SecurityType
	ID           string
	conn         net.Conn
	shared       uint8
	server       *Server
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

func (s *Session) Handshake(major, minor int) {
	s.protocolVersionHandshake(major, minor)
	s.securityHandshake()
}

/*
>>> RFB xxx.xxx\n
<<< RFB xxx.xxx\n
*/
func (s *Session) protocolVersionHandshake(major, minor int) {
	serverVersion := fmt.Sprintf(protocolVersionFormat, major, minor)
	_, err := s.WriteString(serverVersion)
	if err != nil {
		panic(fmt.Errorf("write server version failed: %s", err))
	}
	log.Printf(">>> send ProtocolVersion: %s", serverVersion)

	buf := make([]byte, len(serverVersion))
	_, err = s.ReadFull(buf)
	if err != nil {
		panic(fmt.Errorf("read client version failed: %s", err))
	}
	log.Printf("<<< read ProtocolVersion: %s", string(buf))

	var clientMajor, clientMinor int
	_, err = fmt.Sscanf(string(buf), protocolVersionFormat, &clientMajor, &clientMinor)
	if err != nil {
		panic(fmt.Errorf("scan client version failed: %s", err))
	}

	if clientMajor != 3 || (clientMinor != 3 && clientMinor != 7 && clientMinor != 8) {
		panic(fmt.Errorf("client version invalid: %s", buf))
	}
	s.Major, s.Minor = clientMajor, clientMinor
}

func (s *Session) checkCredential(challenge, response []byte) bool {
	passwd, err := s.readPasswd()
	if err != nil {
		panic(fmt.Errorf("read passwd failed: %s", err))
	}

	keyBuf := make([]byte, 8)

	for i := 0; i < len(passwd); i++ {
		// https://www.vidarholen.net/contents/junk/vnc.html
		keyBuf[i] = ReverseBits(passwd[i])
	}

	encrypted, err := DesEncrypt(keyBuf, challenge)
	if err != nil {
		panic(fmt.Errorf("des encrypt failed: %s", err))
	}
	return bytes.Equal(response, encrypted)
}

func (s *Session) readPasswd() ([]byte, error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}
	p := filepath.Join(u.HomeDir, passwdFile)
	passwd, err := ioutil.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return []byte(strings.TrimSpace(string(passwd))), nil
}

func (s *Session) securityHandshake() {

	sts := []byte{byte(types.STInvalid), byte(types.STNone), byte(types.STVNCAuthentication)}

	buf := make([]byte, len(sts)+1)
	buf[0] = byte(len(sts))
	for i, t := range sts {
		buf[i+1] = t
	}

	_, err := s.Write(buf)
	if err != nil {
		panic(fmt.Errorf("send security types failed: %s", err))
	}
	log.Printf(">>> send security types: %v", buf)

	buf = make([]byte, 1)
	_, err = s.ReadFull(buf)
	if err != nil {
		panic(fmt.Errorf("read client security type failed :%s", err))
	}
	log.Printf("<<< read security types: %v", buf)

	st := types.SecurityType(buf[0])
	s.securityType = st
	log.Printf("client security type: %d", s.securityType)

	var failedReson error = nil
	if st == types.STNone {
		// pass to security type result handshake
	} else if st == types.STVNCAuthentication {
		challenge := make([]byte, 16)
		_, err := rand.Read(challenge)
		if err != nil {
			panic(fmt.Errorf("generate VNC authentication challenge failed: %s", err))
		}

		_, err = s.Write(challenge)
		if err != nil {
			panic(fmt.Errorf("send VNC authentication challenge failed: %s", err))
		}
		log.Printf(">>> send VNC authentication challenge: %v", challenge)

		response := make([]byte, 16)
		_, err = s.ReadFull(response)
		if err != nil {
			panic(fmt.Errorf("read VNC authentication response failed: %s", err))
		}
		log.Printf("<<< read VNC authentication response: %v", response)

		if !s.checkCredential(challenge, response) {
			log.Printf("check credential failed")
			failedReson = keyErr
		}
	} else {
		msg := "the server cannot support the desired protocol version"
		err := s.WriteUint32(uint32(len(msg)))
		if err != nil {
			panic(fmt.Errorf("send security type error msg failed: %s", err))
		}
		_, err = s.Write([]byte(msg))
		if err != nil {
			panic(fmt.Errorf("send security type error msg failed: %s", err))
		}
		panic(fmt.Errorf("security handshake failed: %s", msg))
	}
	s.securityResultHandshake(failedReson)
}

func (s *Session) securityResultHandshake(reason error) {
	stres := types.STROk
	if reason != nil {
		stres = types.STRFailed
	}

	err := s.WriteUint32(uint32(stres))
	if err != nil {
		panic(fmt.Errorf("send security result failed:%s", err))
	}
	log.Printf(">>> send security result: %d", stres)
	if stres == types.STRFailed {
		err := s.WriteUint32(uint32(len(reason.Error())))
		if err != nil {
			panic(fmt.Errorf("send security type result error msg failed: %s", err))
		}
		_, err = s.Write([]byte(reason.Error()))
		if err != nil {
			panic(fmt.Errorf("send security type result error msg failed: %s", err))
		}
		panic(fmt.Errorf("security handshake result failed: %s", reason))
	} else if stres == types.STROk {
		// pass to the initialization phase
	} else {
		panic(fmt.Errorf("not supported security type result: %d", stres))
	}
	log.Println("security type negotiation successful")
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
	sim := &types.ServerInitMessage{
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

		cmt := types.ClientMessageType(u8)
		log.Printf("<<< read client message type: %d <%s>", u8, types.TranslateClientMessageType(cmt))

		switch cmt {
		case types.CMTSetPixelFormat:
			s.setPixelFormat()
		case types.CMTSetEncodings:
			s.setEncodings()
		case types.CMTFramebufferUpdateRequest:
			s.framebufferUpdateRequest()
		case types.CMTKeyEvent:
			s.keyEvent()
		case types.CMTPointerEvent:
			s.pointerEvent()
		case types.CMTClientCutText:
			s.clientCutText()
		default:
			panic(fmt.Errorf("unknown client message type: %d", cmt))
		}
	}
}

func (s *Session) serverPixelFormat() *types.PixelFormat {
	return s.server.defaultPF
}

func (s *Session) setServerPixelFormat(pf *types.PixelFormat) {
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
	pf, err := types.NewPixelFormat(buf)
	if err != nil {
		panic(fmt.Errorf("new pixel format failed: %s", err))
	}
	s.setServerPixelFormat(pf)
	log.Printf(">>> read pixel format: %v, %+v", buf, pf)

	if pf.TrueColorFlag == 0 {
		s.setColorMapEntries()
	}
}

func (s *Session) setServerEncodings(encodings types.Encodings) {
	s.server.encodings = encodings
}

func (s *Session) serverEncodings() types.Encodings {
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

	encodings := make(types.Encodings, encLen)
	for i := uint16(0); i < encLen; i++ {
		enc, err := s.ReadInt32()
		if err != nil {
			panic(fmt.Errorf("read encodings failed: %s", err))
		}
		encodings[i] = types.Encoding(enc)
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

	fbur, err := types.NewFramebufferUpdateRequest(buf)
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

	ke, err := types.NewKeyEvent(buf)
	if err != nil {
		panic(fmt.Errorf("new key event failed: %s", err))
	}
	log.Printf(">>> read key event: %v, %+v", buf, ke)
}

func (s *Session) pointerEvent() {
	log.Println("handle pointerEvent")
	buf := make([]byte, 5)
	_, err := s.ReadFull(buf)
	if err != nil {
		panic(fmt.Errorf("read pointer event failed: %s", err))
	}
	pe, err := types.NewPointerEvent(buf)
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
