PREFIX ?= /usr
DEB_ARCH ?= amd64

.PHONY: all build build-frontend build-x86_64-musl deb deploy clean

DEPLOY_HOST ?= oracle
DEB_NAME ?= laputa-mirror_0.1.0_$(DEB_ARCH).deb

all: build build-frontend

build:
	cargo build --locked

build-x86_64-musl:
	mkdir -p target/docker-output
	docker buildx build \
	  --platform linux/amd64 \
	  --output type=local,dest=target/docker-output \
	  .

build-frontend:
	deno install --frozen
	deno task build

deb: build-x86_64-musl build-frontend
	rm -rf target/deb-root
	install -d target/deb-root/DEBIAN
	install -d target/deb-root/usr/bin
	install -d target/deb-root/lib/systemd/system
	install -d target/deb-root/etc/laputa-mirror
	install -d target/deb-root/usr/share/laputa-mirror
	install -m 755 target/docker-output/laputa-mirror target/deb-root/usr/bin/laputa-mirror
	install -m 755 target/docker-output/laputa-mirror-publish target/deb-root/usr/bin/laputa-mirror-publish
	install -m 644 laputa-mirror.service target/deb-root/lib/systemd/system/laputa-mirror.service
	install -m 600 laputa-mirror.env.example target/deb-root/etc/laputa-mirror/env.example
	cp -R static target/deb-root/usr/share/laputa-mirror/
	printf '%s\n' \
	  'Package: laputa-mirror' \
	  'Version: 0.1.0' \
	  "Architecture: $(DEB_ARCH)" \
	  'Maintainer: Laputa Systems' \
	  'Description: Laputa package mirror' \
	  > target/deb-root/DEBIAN/control
	printf '%s\n' \
	  '#!/bin/sh' \
	  'set -e' \
	  'if ! getent passwd laputa-mirror >/dev/null; then' \
	  '  useradd --system --home /var/lib/laputa-mirror --shell /usr/sbin/nologin laputa-mirror' \
	  'fi' \
	  'install -d -o laputa-mirror -g laputa-mirror /var/lib/laputa-mirror' \
	  'if [ ! -f /etc/laputa-mirror/env ]; then' \
	  '  install -m 600 -o root -g root /etc/laputa-mirror/env.example /etc/laputa-mirror/env' \
	  'fi' \
	  'if command -v systemctl >/dev/null; then' \
	  '  systemctl daemon-reload || true' \
	  'fi' \
	  > target/deb-root/DEBIAN/postinst
	chmod 755 target/deb-root/DEBIAN/postinst
	dpkg-deb --root-owner-group --build target/deb-root $(DEB_NAME)

deploy: deb
	scp "$(DEB_NAME)" "$(DEPLOY_HOST):/tmp/$(DEB_NAME)"
	ssh "$(DEPLOY_HOST)" "set -eu; sudo dpkg -i /tmp/$(DEB_NAME); sudo systemctl daemon-reload; sudo systemctl restart laputa-mirror; sudo systemctl enable --now laputa-mirror; sudo systemctl status --no-pager laputa-mirror"

clean:
	rm -rf node_modules
	rm -f static/js/auth.js static/js/settings.js
	rm -rf target/deb-root target/docker-output
