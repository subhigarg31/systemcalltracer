.PHONY: all build build-sim install test start clean

all: build-sim build

install:
	cd server && npm install
	cd client && npm install

build-sim:
	$(MAKE) -C simulator

build: build-sim
	cd client && npm run build

test:
	cd server && npm test

start:
	cd server && npm start

dev-client:
	cd client && npm run dev

clean:
	$(MAKE) -C simulator clean
	rm -rf client/dist
