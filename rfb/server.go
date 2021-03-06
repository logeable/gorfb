package rfb

import (
	"context"
	"fmt"
	"log"
	"net"

	"bufio"

	"github.com/google/uuid"
	"github.com/logeable/gorfb/rfb/messages"
)

func NewServer() *Server {
	return &Server{
		Major:  3,
		Minor:  8,
		Width:  800,
		Height: 600,
		Name:   "RFB Server",
		defaultPF: &messages.PixelFormat{
			// 8, 16, 32
			BitsPerPixel: 32,
			Depth:        32,
			BigEndian:    0,
			TrueColor:    1,
			RedMax:       255,
			GreenMax:     255,
			BlueMax:      255,
			RedShift:     16,
			GreenShift:   8,
			BlueShift:    0,
		},
		securityTypes: []messages.SecurityType{messages.STNone, messages.STVNCAuthentication},
	}
}

type Server struct {
	Major, Minor  int
	Width, Height uint16
	Name          string
	sessions      map[string]*Session
	listener      net.Listener
	defaultPF     *messages.PixelFormat
	encodings     messages.Encodings
	securityTypes messages.SecurityTypes
}

func (s *Server) ListenAndServe(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening failed: %s", err)
	}
	defer listener.Close()
	s.listener = listener

	log.Printf("RFB server listening on: %s", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("accept failed: %s", err)
		}
		go s.HandleConnection(conn)
	}
}

func (s *Server) CleanSession(session *Session) {
	log.Printf("clean session: %s, %s", session.ID, session.conn.RemoteAddr())
	session.conn.Close()
}

func (s *Server) CleanSessionExcept(session *Session) {
	for _, sess := range s.sessions {
		if sess == session {
			continue
		}
		s.CleanSession(session)
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		for _, session := range s.sessions {
			s.CleanSession(session)
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("RFB server shutdown interrupt: %s", ctx.Err())
	case <-done:
		return nil
	}
}

func (s *Server) AddSession(session *Session) {
	if s.sessions == nil {
		s.sessions = make(map[string]*Session)
	}
	s.sessions[session.ID] = session
}

func (s *Server) HandleConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("new connection: %s", conn.RemoteAddr())

	session := &Session{
		ID:     uuid.New().String(),
		conn:   conn,
		server: s,
		bufrw:  bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn)),
	}
	defer s.CleanSession(session)

	s.AddSession(session)

	panicChan := make(chan interface{})
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				panicChan <- r
			}
		}()
		session.Serve()
		close(done)
	}()

	select {
	case r := <-panicChan:
		log.Printf("session panic, %s: %v", session.ID, r)
		return
	case <-done:
		log.Printf("session serve done: %s", session.ID)
	}
}
