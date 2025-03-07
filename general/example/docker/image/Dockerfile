# build and run docker.go 
FROM golang:alpine
RUN mkdir /app

ADD docker.go /app/
WORKDIR /app

RUN go build docker.go
CMD ["./docker"]

#  example build docker command and execute command 
#  docker build -t example .
#  docker run example