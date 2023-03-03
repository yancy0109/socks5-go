## 介绍
基于GO，SOCKS5服务器，目前仅支持无验证/密码验证方式

```go
// 示例
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
				return serverPassword == password && serverUsername == username
			},
		},
	}
	err := server.Run()
	if err != nil {
		log.Fatalln(err)
	}
}
```

待完善