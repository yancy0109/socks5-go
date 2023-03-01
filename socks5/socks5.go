package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

var (
	ErrMethodNotSupport     = errors.New("method not supported")
	ErrVersionNotSupported  = errors.New("protocol version not supported")
	ErrCommandNotSupported  = errors.New("command not supported")
	ErrInvalidReservedField = errors.New("invalid reserved field")
	ErrAddressTypeSupported = errors.New("address type not supported")
)

const (
	SOCKS5Version = 0x05
	ReservedField = 0x00
)

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

		// Go
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
	if err := auth(conn); err != nil {
		return err
	}
	// 请求
	targetConn, err := request(conn)
	if err != nil {
		return err
	}
	// 转发
	return forward(conn, targetConn)
}

/**
处理协商
*/
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
		return ErrMethodNotSupport
	}
	return NewServerAuthMessage(conn, MethodNoAuth)
}

/**
处理请求
*/
func request(conn io.ReadWriter) (io.ReadWriteCloser, error) {
	message, err := NewClientRequestMessage(conn)
	if err != nil {
		return nil, err
	}
	// 检验Command支持
	if message.Cmd != CommandConnect {
		// 返回Command不支持
		return nil, WriteRequestFailureMessage(conn, ReplyCommandNotSupported)
	}
	// 检验AddrType
	if message.AddrType != TypeIPv4 && message.AddrType != TypeDomain {
		// 返回AddrType不支持
		return nil, WriteRequestFailureMessage(conn, ReplyAddressTypeNotSupported)
	}

	// 请求访问目标TCP服务
	addrees := fmt.Sprintf("%s:%d", message.Address, message.Port)
	targetConn, err := net.Dial("tcp", addrees)
	if err != nil {
		return nil, WriteRequestFailureMessage(conn, ReplyConnectionRefusd)
	}

	// Send Success Reply
	addrValue := targetConn.LocalAddr()
	addr := addrValue.(*net.TCPAddr)
	return targetConn, WriteRequestSuccessMessage(conn, addr.IP, uint16(addr.Port))
}

/**
转发过程
*/
func forward(conn io.ReadWriter, targetConn io.ReadWriteCloser) error {
	defer targetConn.Close()

	go func() {
		io.Copy(targetConn, conn)
	}()
	_, err := io.Copy(conn, targetConn)
	return err
}
