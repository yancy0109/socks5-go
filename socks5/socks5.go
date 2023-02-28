package socks5

import (
	"errors"
	"fmt"
	"log"
	"net"
)

const SOCKS5Version = 0x05

type Server interface {
	Run() error
}

type SOCKS5Server struct {
	IP   string
	Port int
}

func (s *SOCKS5Server) Run() error {
	address := fmt.Sprintf("%s:%d", s.IP, s.Port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Connection failure from %s: %s ", conn.RemoteAddr(), err)
			continue
		}

		//
		go func() {
			defer conn.Close()
			err := handleConnection(conn)
			if err != nil {
				log.Printf("handle connection failure from %s: %s", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleConnection(conn net.Conn) error {
	// 协商
	err := auth(conn)
	if err != nil {
		return err
	}
	// 请求

	// 转发

	return nil
}

func auth(conn net.Conn) error {
	clientMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}
	// Only support no-auth
	var accpetable bool
	for _, method := range clientMessage.Methods {
		if method == MethodNoAuth {
			accpetable = true
		}
	}

	if !accpetable {
		NewServerAuthMessage(conn, MethodNoAcceptable)
		return errors.New("method not supported")
	}
	return NewServerAuthMessage(conn, MethodNoAuth)
}
