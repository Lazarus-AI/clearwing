REGISTRY ?= clearwing-sourcehunt
PLATFORM ?= linux/amd64

IMAGES = c cpp rust go java node python unknown c-deep c-exploit c-msan

.PHONY: all clean k8s

all: $(IMAGES)

$(IMAGES):
	docker build --platform $(PLATFORM) -t $(REGISTRY)-$@:latest -f Dockerfile.$@ .

# Build all images into k3s/containerd (Rancher Desktop local dev)
# Tags both short and fully-qualified names so kubelet can resolve them.
k8s:
	@for img in $(IMAGES); do \
		echo "▸ clearwing-sourcehunt-$$img:latest"; \
		nerdctl --namespace k8s.io build --platform $(PLATFORM) -t $(REGISTRY)-$$img:latest -t docker.io/library/$(REGISTRY)-$$img:latest -f Dockerfile.$$img . || exit 1; \
	done

clean:
	@for img in $(IMAGES); do \
		docker rmi $(REGISTRY)-$$img:latest 2>/dev/null || true; \
	done
