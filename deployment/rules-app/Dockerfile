FROM metasploitframework/metasploit-framework:latest

RUN apk update && apk add --no-cache \
    tcpdump \
    tshark

WORKDIR /app

COPY . .

RUN go build -o server ./cmd

EXPOSE 8080

ENTRYPOINT ["/bin/sh", "-c", "./server"]