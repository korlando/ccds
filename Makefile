port="8030"
binary=CCDSDevServer
binaryprod=CCDSProdServer
wd=$(shell pwd)
awshome=$(CCDS_AWS_HOME_PATH)
key=$(CCDS_SSH_KEY_PATH)
sshhost=$(CCDS_AWS_HOST)
build:
	go build -o bin/$(binary) cmd/server/server.go
buildprod:
	GOOS=linux GOARCH=amd64 go build -o bin/$(binaryprod) cmd/server/server.go
run:
	./bin/$(binary) --port=$(port)
runprod:
	./bin/$(binaryprod) --port=$(port) --production
initdaemon:
	touch ./ccds.log && \
	touch ./ccds.pid && \
	touch ./ccds.lock
start:
	make initdaemon && \
	daemonize -a -e $(wd)/ccds.log -p $(wd)/ccds.pid -l $(wd)/ccds.lock $(wd)/bin/$(binary) --port=$(port)
startprod:
	make initdaemon && \
	daemonize -a -e $(wd)/ccds.log -p $(wd)/ccds.pid -l $(wd)/ccds.lock $(wd)/bin/$(binaryprod) --port=$(port) --production
stop:
	killall $(binaryprod) $(binary) || true
restart:
	make stop && make start
push:
	ssh -t -i $(key) $(sshhost) "mkdir -p $(awshome)/ccds && mkdir -p $(awshome)/ccds/bin" && \
	scp -i $(key) ./bin/$(binaryprod) $(sshhost):$(awshome)/ccds/bin/$(binaryprod)
