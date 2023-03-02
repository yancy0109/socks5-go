# FROM ... AS builder : 表示依赖的镜像只是使用在编译阶段
FROM golang:1.18.1 AS builder

# 编译阶段的工作目录，也可以作为全局工作目录
WORKDIR /app

# 把当前目录的所有内容copy到 WORKDIR指定的目录中
COPY . /app

RUN go build -o /app/Socks5 /app/main/main.go

CMD ./app/Socks5