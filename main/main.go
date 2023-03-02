package main

import (
	"fmt"
	"github.com/yancy0109/socks5-go/socks5"
	"log"
	"os"
	"strconv"
)

func main() {
	serverUsername := "asdpg612897a.*.."
	serverPassword := "sdamzs029123//.."
	serverPort := 1080
	if len(os.Args) > 3 {
		fmt.Println("your username is", os.Args[1])
		fmt.Println("your password is", os.Args[2])
		fmt.Println("your server port is", os.Args[3])
		serverUsername = os.Args[1]
		serverPassword = os.Args[2]
		result, err := strconv.Atoi(os.Args[3])
		if err == nil {
			serverPort = result
		}
	}

	server := socks5.SOCKS5Server{
		IP:   "localhost",
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
