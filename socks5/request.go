package socks5

import (
	"io"
	"net"
)

const (
	IPv4Length = 4
	IPv6Length = 6
	PortLength = 2
)

type ClientRequestMessage struct {
	Cmd      Command
	AddrType AddressType
	Address  string
	Port     uint16
}

type Command = byte

const (
	CommandConnect Command = 0x01
	CommandBind    Command = 0x02
	CommandUDP     Command = 0x03
)

type AddressType = byte

const (
	TypeIPv4   AddressType = 0x01
	TypeDomain AddressType = 0x03
	TypeIPv6   AddressType = 0x04
)

func NewClientRequestMessage(conn io.Reader) (*ClientRequestMessage, error) {
	// Read version, command, reserved, address type
	buf := make([]byte, IPv4Length)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	version, command, reserved, addrType := buf[0], buf[1], buf[2], buf[3]
	// 检查SOCKS5版本
	if version != SOCKS5Version {
		return nil, ErrVersionNotSupported
	}
	// 检查Command
	if command != CommandConnect && command != CommandUDP && command != CommandBind {
		return nil, ErrCommandNotSupported
	}
	// 检查Reserved
	if reserved != ReservedField {
		return nil, ErrInvalidReservedField
	}
	// 检查AddressTpye
	if addrType != TypeIPv4 && addrType != TypeDomain && addrType != TypeIPv6 {
		return nil, ErrAddressTypeSupported
	}

	// Read address and port
	message := ClientRequestMessage{
		Cmd:      command,
		AddrType: addrType,
	}

	// 根据AddrType构建Address
	switch addrType {
	case TypeIPv6:
		buf = make([]byte, IPv6Length)
		// 交由下方继续处理
		fallthrough
	case TypeIPv4:
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip := net.IP(buf)
		message.Address = ip.String()
	case TypeDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return nil, err
		}
		domainLength := buf[0]
		if domainLength > IPv4Length {
			buf = make([]byte, domainLength)
		}
		// read Domain
		if _, err := io.ReadFull(conn, buf[:domainLength]); err != nil {
			return nil, err
		}
		message.Address = string(buf[:domainLength])

	}
	// read port
	if _, err := io.ReadFull(conn, buf[:PortLength]); err != nil {
		return nil, err
	}
	message.Port = uint16(buf[0])<<8 + uint16(buf[1])
	return &message, nil
}

type ReplyType = byte

const (
	ReplySuccess ReplyType = iota
	ReplyServerFailure
	ReplyConnectionNotAllowed
	ReplyNetworkUnreachable
	ReplyHostUnreachable
	ReplyConnectionRefusd
	ReplyTTLExpired
	ReplyCommandNotSupported
	ReplyAddressTypeNotSupported
)

func WriteRequestSuccessMessage(conn io.Writer, ip net.IP, port uint16) error {
	// 目前仅支持IPv4/IPv6
	addressType := TypeIPv4
	if len(ip) == IPv6Length {
		addressType = TypeIPv6
	}
	// Write Version, reply success, reserved, address type
	_, err := conn.Write([]byte{SOCKS5Version, ReplySuccess, ReservedField, addressType})
	if err != nil {
		return err
	}
	// Write bind IP(IPv4, IPv6)
	_, err = conn.Write(ip)
	if err != nil {
		return err
	}

	//  Write bind port
	buf := make([]byte, 2)
	// 大端传输
	buf[0] = byte(port >> 8)
	buf[1] = byte(port)
	_, err = conn.Write(buf)
	return err
}

func WriteRequestFailureMessage(conn io.Writer, replyType ReplyType) error {
	_, err := conn.Write([]byte{SOCKS5Version, replyType, ReservedField, TypeIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
