package rfb

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os/user"
	"path/filepath"
)

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
