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

	"github.com/logeable/gorfb/utils"
)

const (
	protocolVersionFormat = "RFB %03d.%03d\n"
	passwdFile            = ".rfbpasswd"
	keyLen                = 8
)

var (
	keyErr = fmt.Errorf("key invalid")
)

type Session struct {
	Major, Minor int
	securityType SecurityType
	ID           string
	conn         net.Conn
}

func (s *Session) ReadFull(buf []byte) (int, error) {
	return io.ReadFull(s.conn, buf)
}

func (s *Session) Write(buf []byte) (int, error) {
	return s.conn.Write(buf)
}

func (s *Session) WriteString(str string) (int, error) {
	return s.conn.Write([]byte(str))
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

	key := make([]byte, keyLen)
	for i := 0; i < len(passwd); i++ {
		// https://www.vidarholen.net/contents/junk/vnc.html
		key[i] = utils.ReverseBits(passwd[i])
	}

	encrypted, err := utils.DesEncrypt(key, challenge)
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

	sts := []byte{byte(stInvalid), byte(stNone), byte(stVNCAuthentication)}

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

	st := SecurityType(buf[0])
	s.securityType = st
	log.Printf("client security type: %d", s.securityType)

	var failedReson error = nil
	if st == stNone {
		// pass to security type result handshake
	} else if st == stVNCAuthentication {
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
	stres := strOk
	if reason != nil {
		stres = strFailed
	}

	err := s.WriteUint32(uint32(stres))
	if err != nil {
		panic(fmt.Errorf("send security result failed:%s", err))
	}
	log.Printf(">>> send security result: %d", stres)
	if stres == strFailed {
		err := s.WriteUint32(uint32(len(reason.Error())))
		if err != nil {
			panic(fmt.Errorf("send security type result error msg failed: %s", err))
		}
		_, err = s.Write([]byte(reason.Error()))
		if err != nil {
			panic(fmt.Errorf("send security type result error msg failed: %s", err))
		}
		panic(fmt.Errorf("security handshake result failed: %s", reason))
	} else if stres == strOk {
		// pass to the initialization phase
	} else {
		panic(fmt.Errorf("not supported security type result: %d", stres))
	}
	log.Println("security type negotiation successful")
}
