package socks5

import (
	"errors"
	"io"
)

type Method = byte

// ClientAuthMessage
// 认证返回 /**
type ClientAuthMessage struct {
	Version  byte
	NMethods byte
	Methods  []Method
}

type ClientPassWordMessage struct {
	Username string
	Password string
}

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPassword     Method = 0x02
	MethodNoAcceptable Method = 0xff
)

const (
	PasswordMethodVersion = 0x01
	PasswordAuthSuccess   = 0x00
	PasswordAuthFailure   = 0x01
)

var (
	ErrPasswordAuthFailure   = errors.New("error authenticating username or password")
	ErrPasswordCheckerNotSet = errors.New("did not set password checker for server")
)

// NewClientAuthMessage
// 通过Reader读取并返回认证信息 /**
func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {
	// Read version, nMethods
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	// Validate version
	if buf[0] != SOCKS5Version {
		return nil, ErrVersionNotSupported
	}

	// Read methods
	nmethods := buf[1]
	buf = make([]byte, nmethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	return &ClientAuthMessage{
		Version:  SOCKS5Version,
		NMethods: nmethods,
		Methods:  buf,
	}, nil
}

func NewServerAuthMessage(conn io.Writer, method Method) error {
	buf := []byte{SOCKS5Version, method}
	_, err := conn.Write(buf)
	return err
}

func NewClientPasswordMessage(conn io.Reader) (*ClientPassWordMessage, error) {
	// Read veresion and username length
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	version, usernameLen := buf[0], buf[1]
	if version != PasswordMethodVersion {
		return nil, ErrMethodVersionNotSupported
	}
	// Read username, passwordLength
	buf = make([]byte, usernameLen+1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	username, passwordLen := string(buf[:len(buf)-1]), buf[len(buf)-1]
	// Read password
	if int(passwordLen) > len(buf) {
		buf = make([]byte, passwordLen)
	}
	if _, err := io.ReadFull(conn, buf[:passwordLen]); err != nil {
		return nil, err
	}
	return &ClientPassWordMessage{
		username,
		string(buf[:passwordLen]),
	}, nil
}

func WriteServerPasswordResponse(conn io.Writer, status byte) error {
	_, err := conn.Write([]byte{PasswordMethodVersion, status})
	return err
}
