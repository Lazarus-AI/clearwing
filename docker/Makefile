IMAGES := c cpp rust go java node python unknown

GIT_HASH := $(shell git -C $(dir $(abspath $(lastword $(MAKEFILE_LIST)))) rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE     := $(shell date +%Y%m%d)

# C/C++ toolchains crawl under qemu on Apple Silicon — build them host-native
# there. Everything else pins amd64 for cross-host reproducibility.
HOST_ARCH := $(shell uname -m)
ifeq ($(HOST_ARCH),arm64)
PLAT_c   := linux/arm64
PLAT_cpp := linux/arm64
endif
PLAT_c    ?= linux/amd64
PLAT_cpp  ?= linux/amd64
PLAT_rust ?= linux/amd64
PLAT_go   ?= linux/amd64
PLAT_java ?= linux/amd64
PLAT_node ?= linux/amd64
PLAT_python  ?= linux/amd64
PLAT_unknown ?= linux/amd64

.PHONY: all $(IMAGES)

all: $(IMAGES)

# Cache probe checks the image is present AT THE TARGET PLATFORM (arch alone
# is enough — Linux is always Linux for our purposes).
$(IMAGES):
	@[ "linux/$$(docker image inspect clearwing-sourcehunt-$@:latest --format '{{.Architecture}}' 2>/dev/null)" = "$(PLAT_$@)" ] && \
		echo "// CACHED  clearwing-sourcehunt-$@ ($(PLAT_$@))" || \
		(echo "// BUILDING  clearwing-sourcehunt-$@ ($(PLAT_$@))" && \
		docker build --platform $(PLAT_$@) \
			-t clearwing-sourcehunt-$@:latest \
			-t clearwing-sourcehunt-$@:$(GIT_HASH) \
			-t clearwing-sourcehunt-$@:$(DATE) \
			-f $(dir $(abspath $(lastword $(MAKEFILE_LIST))))Dockerfile.$@ \
			$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
