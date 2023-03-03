package main

import (
	"fmt"
	"github.com/yancy0109/socks5-go/socks5"
	"log"
	"os"
	"strconv"
)

func main() {
	serverUsername := "admin"
	serverPassword := "admin"
	serverAddress := "localhost"
	serverPort := 11451
	if len(os.Args) > 3 {
		serverUsername = os.Args[1]
		serverPassword = os.Args[2]
		result, err := strconv.Atoi(os.Args[3])
		serverAddress = os.Args[4]
		if err == nil {
			serverPort = result
		}
	}

	fmt.Println("your username is", serverUsername)
	fmt.Println("your password is", serverPassword)
	fmt.Println("your server port is", serverPort)

	server := socks5.SOCKS5Server{
		IP:   serverAddress,
		Port: serverPort,
		Config: &socks5.Config{
			AuthMethod: socks5.MethodPassword,
			PasswordChecker: func(username, password string) bool {
				// Restore in Map
				//wantPassword, ok := users[username]
				//if !ok {
				//	return false
				//}
				// Infer By Os.Args
				//return wantPassword == password
				return serverPassword == password && serverUsername == username
			},
		},
	}
	err := server.Run()
	if err != nil {
		log.Fatalln(err)
	}
}
