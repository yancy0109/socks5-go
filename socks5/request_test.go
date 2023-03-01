package socks5

import (
	"bytes"
	"net"
	"reflect"
	"testing"
)

func TestNewClientRequestMessage(t *testing.T) {
	t.Run("test new client request message, use valid tcp request", func(t *testing.T) {
		tests := []struct {
			Version  byte
			Cmd      Command
			AddrType AddressType
			Address  []byte
			Port     []byte
			Error    error
			Message  ClientRequestMessage
		}{
			{
				Version:  SOCKS5Version,
				Cmd:      CommandConnect,
				AddrType: TypeIPv4,
				Address:  []byte{123, 25, 13, 89},
				Port:     []byte{0x00, 0x50},
				Error:    nil,
				Message: ClientRequestMessage{
					Cmd:      CommandConnect,
					AddrType: TypeIPv4,
					Address:  "123.25.13.89",
					Port:     0x0050,
				},
			}, {
				Version:  0x00,
				Cmd:      CommandConnect,
				AddrType: TypeIPv4,
				Address:  []byte{123, 25, 13, 89},
				Port:     []byte{0x00, 0x50},
				Error:    ErrVersionNotSupported,
				Message: ClientRequestMessage{
					Cmd:      CommandConnect,
					AddrType: TypeIPv4,
					Address:  "123.25.13.89",
					Port:     0x0050,
				},
			},
		}
		for _, test := range tests {
			buf := bytes.Buffer{}
			buf.Write([]byte{test.Version, test.Cmd, ReservedField, test.AddrType})
			buf.Write(test.Address)
			buf.Write(test.Port)

			message, err := NewClientRequestMessage(&buf)
			if err != test.Error {
				t.Fatalf("should get error %s, but got %s\n", test.Error, err)
			}
			if err != nil {
				continue
			}
			if *message != test.Message {
				t.Fatalf("should get message %v, but got %v\n", test.Message, *message)
			}
		}
	})
}

func TestProcessPort(t *testing.T) {
	t.Run("process port", func(t *testing.T) {
		buf := []byte{0x00, 0x50}
		port := (uint16(buf[0]) << 8) + uint16(buf[1])
		if port != 0x0050 {
			t.Fatalf("should get port %v, but got %v\n", 0x50, port)
		}
	})
}

func TestWriteRequestSuccessMessage(t *testing.T) {
	t.Run("test Write Request Success Message", func(t *testing.T) {
		var buf bytes.Buffer
		ip := net.IP([]byte{123, 123, 11, 11})

		err := WriteRequestSuccessMessage(&buf, ip, 1081)
		if err != nil {
			t.Fatalf("error while writing: %s", err)
		}

		want := []byte{
			SOCKS5Version,
			ReplySuccess,
			ReservedField,
			TypeIPv4,
			123, 123, 11, 11,
			0x04, 0x39,
		}
		got := buf.Bytes()
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("message not match, want %v, got %v", want, buf)
		}
	})
}
