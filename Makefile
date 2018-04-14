wd=$(shell pwd)
awshome=$(CCDS_AWS_HOME_PATH)
key=$(CCDS_SSH_KEY_PATH)
sshhost=$(CCDS_AWS_HOST)
version=$(shell cat .version)
versionprod=$(shell cat .versionprod)
port=8030
name=CCDSDevServer
nameprod=CCDSProdServer
binary=$(name)V$(version)
binaryprod=$(nameprod)V$(versionprod)
buildincrement:
	go build -o bin/increment cmd/increment/increment.go
# build before incrementing in case build fails
build: buildincrement
	go build -o bin/DEVBUILD cmd/server/server.go && \
	new=$$(./bin/increment $(version)) && \
	echo $$new > .version && \
	mv bin/DEVBUILD bin/$(name)V$$new
buildprod: buildincrement
	GOOS=linux GOARCH=amd64 go build -o bin/PRODBUILD cmd/server/server.go && \
	new=$$(./bin/increment $(versionprod)) && \
	echo $$new > .versionprod && \
	mv bin/PRODBUILD bin/$(nameprod)V$$new
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
