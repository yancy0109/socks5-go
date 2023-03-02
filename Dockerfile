# FROM ... AS builder : 表示依赖的镜像只是使用在编译阶段
FROM golang:1.18.1 AS builder

# 编译阶段的工作目录，也可以作为全局工作目录
WORKDIR /app

# 把当前目录的所有内容copy到 WORKDIR指定的目录中
COPY . .

# 执行go build； --mount：在执行build时，会把/go 和 /root/.cache/go-build 临时挂在到容器中
RUN --mount=type=cache,target=/go --mount=type=cache,target=/root/.cache/go-build \
    GOOS=linux GOARCH=amd64 go build -o Socks5 ./main/main.go

FROM alpine:3.14.0

# 把执行builder阶段的结果 /app/main拷贝到/app中
COPY --from=builder /app/Socks5 /app

# 运行main命令，启动项目
# /app/main 指向RUN命令的 go build -o main的结果
ENTRYPOINT ["/app/Socks5"]