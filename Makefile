# LGroot — build helpers.
#
#   make            release binary
#   make app        macOS .app bundle in dist/
#   make run        run from the working tree
#   make test       unit tests + end-to-end test against a mock TV
#   make icon       regenerate assets/AppIcon.icns
#   make clean      remove build output

CARGO ?= cargo

.PHONY: all build app run test icon clean

all: build

build:
	$(CARGO) build --release

app:
	sh scripts/make_app.sh

run:
	$(CARGO) run

test:
	$(CARGO) test

icon:
	python3 scripts/make_icon.py

clean:
	$(CARGO) clean
	rm -rf dist
