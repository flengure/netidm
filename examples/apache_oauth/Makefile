# set the following environment variables
# OAUTH_HOSTNAME       - the hostname you'll be exposing this as
# OAUTH_PORT           - the external port this'll be running on (sets it in --publish)
#                        this is 8553, but ... things get weird if the stack doesn't end up being accessed
#                        through 443, eg via a tunneled proxy
# NETIDM_HOSTNAME      - the hostname of the Netidm instance
# NETIDM_PORT          - if you're running it on a different port
# NETIDM_CLIENT_SECRET - the client secret for the RP in Netidm's OAuth config
NETIDM_PORT ?= 443
OAUTH_PORT ?= 8553

.DEFAULT: build_and_run

.PHONY: build_and_run
build_and_run: build run

.PHONY: build
build:
	docker build -t netidm_oauth_test:latest .

.PHONY: run
run:
	docker rm -f netidm_oauth_test
	docker run --rm -it \
		--env OAUTH_HOSTNAME=$(OAUTH_HOSTNAME) \
		--env NETIDM_HOSTNAME=$(NETIDM_HOSTNAME) \
		--env NETIDM_PORT=$(NETIDM_PORT) \
		--env NETIDM_CLIENT_SECRET=$(NETIDM_CLIENT_SECRET) \
		--volume /tmp/netidm/:/certs/ \
		--publish "$(OAUTH_PORT):443" \
		--name netidm_oauth_test \
		netidm_oauth_test:latest
