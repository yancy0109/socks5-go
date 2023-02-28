package main

import (
	"github.com/yancy0109/socks5-go/socks5"
	"log"
)

func main() {
	server := socks5.SOCKS5Server{
		IP:   "localhost",
		Port: 1080,
	}
	err := server.Run()
	if err != nil {
		log.Fatalln(err)
	}
}
