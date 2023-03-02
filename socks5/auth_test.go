package socks5

import (
	"bytes"
	"reflect"
	"testing"
)

func TestNewClientAuthMessage(t *testing.T) {
	// 单元测试示例
	t.Run("should generate a message", func(t *testing.T) {
		b := []byte{
			SOCKS5Version,
			2,
			MethodNoAuth, MethodGSSAPI,
		}
		reader := bytes.NewReader(b)
		message, err := NewClientAuthMessage(reader)
		if err != nil {
			t.Fatalf("want error = nil but got %s", err)
		}
		if message.Version != SOCKS5Version {
			t.Fatalf("want SOCKS5Version but got %s", err)
		}
		if message.NMethods != 2 {
			t.Fatalf("want nmethods = 2 but got %s", err)
		}
		wantMethods := []byte{MethodNoAuth, MethodGSSAPI}
		if !reflect.DeepEqual(message.Methods, wantMethods) {
			t.Fatalf("want methods: %v but got %v", wantMethods, message.Methods)
		}
	})
}

func TestNewServerAuthMessage(t *testing.T) {
	t.Run("server response", func(t *testing.T) {
		buffer := bytes.Buffer{}
		err := NewServerAuthMessage(&buffer, MethodNoAuth)
		if err != nil {
			t.Fatalf("should get nil error but got %s", err)
		}
		got := buffer.Bytes()
		wantGot := []byte{SOCKS5Version, MethodNoAuth}
		if !reflect.DeepEqual(got, wantGot) {
			t.Fatalf("want methods: %v but got %v", wantGot, got)
		}
	})
}

func TestNewClientPasswordMessage(t *testing.T) {
	t.Run("valid password auth message", func(t *testing.T) {
		username, password := "admin", "123"
		buf := bytes.Buffer{}
		buf.Write([]byte{PasswordMethodVersion, 5})
		buf.WriteString(username)
		buf.WriteByte(3)
		buf.WriteString(password)
		message, err := NewClientPasswordMessage(&buf)
		if err != nil {
			t.Fatalf("want error = nil, but got %s", err)
		}
		want := ClientPassWordMessage{
			username, password,
		}
		if *message != want {
			t.Fatalf("want message %v but got %v", *message, want)
		}
	})
}
