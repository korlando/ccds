wd=$(shell pwd)
awshome=$(CCDS_AWS_HOME_PATH)
key=$(CCDS_SSH_KEY_PATH)
sshhost=$(CCDS_AWS_HOST)
version=$(shell cat .version)
versionprod=$(shell cat .versionprod)
port="8030"
name=CCDSDevServer
nameprod=CCDSProdServer
binary=$(name)V$(version)
binaryprod=$(nameprod)V$(versionprod)
buildincrement:
	go build -o bin/increment cmd/increment/increment.go
increment: buildincrement
	./bin/increment $(version) > .version
incrementprod: buildincrement
	./bin/increment $(versionprod) > .versionprod
build: increment
	go build -o bin/$(name)V$(shell cat .version) cmd/server/server.go
buildprod: incrementprod
	GOOS=linux GOARCH=amd64 go build -o bin/$(nameprod)V$(shell cat .versionprod) cmd/server/server.go
run:
	./bin/$(binary) --port=$(port)
runprod:
	./bin/$(binaryprod) --port=$(port) --production
initdaemon:
	touch ccds.log && \
	touch ccds.pid && \
	touch ccds.lock
start: initdaemon
	daemonize -a -e $(wd)/ccds.log -p $(wd)/ccds.pid -l $(wd)/ccds.lock $(wd)/bin/$(binary) --port=$(port)
startprod: initdaemon
	daemonize -a -e $(wd)/ccds.log -p $(wd)/ccds.pid -l $(wd)/ccds.lock $(wd)/bin/$(binaryprod) --port=$(port) --production
stop:
	pgrep $(name) | xargs kill || true
stopprod:
	pgrep $(nameprod) | xargs kill || true
restart: stop start
restartprod: stopprod startprod
push:
	ssh -t -i $(key) $(sshhost) "mkdir -p $(awshome)/ccds && mkdir -p $(awshome)/ccds/bin" && \
	scp -i $(key) ./bin/$(binaryprod) $(sshhost):$(awshome)/ccds/bin/$(binaryprod)
