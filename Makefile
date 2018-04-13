port="8030"
binary="server"
binaryprod="ccdsapi"
build:
	go build -o bin/$(binary) cmd/server/server.go
buildprod:
	GOOS=linux GOARCH=amd64 go build -o bin/$(binaryprod) cmd/server/server.go
run:
	./bin/$(binary) --port=$(port)
runprod:
	./bin/$(binaryprod) --port=$(port) --production
