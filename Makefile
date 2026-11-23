BINARY   := tracing_service
IMAGE    := tracing
REGISTRY := registry.home.arpa

KERNEL_VERSION := $(shell uname -r)
BPF_INCLUDES := -I/usr/lib/modules/$(KERNEL_VERSION)/build/include \
                -I/usr/lib/modules/$(KERNEL_VERSION)/build/arch/x86/include/generated \
                -I/usr/lib/modules/$(KERNEL_VERSION)/build/arch/x86/include \
                -I/usr/lib/modules/$(KERNEL_VERSION)/build/include/linux \
                -I/usr/lib/modules/$(KERNEL_VERSION)/build
TARGET := bpfel
GOPACKAGE := tracing_service
OUTPUT_DIR := ./pkg/${GOPACKAGE}
OUTPUT_STEM := packet_logging_bpf
BPF_SOURCE := tracing.bpf.c

.PHONY: all bpf build test fmt vet image guard-release-versions publish clean

all: build

bpf:
	GOPACKAGE=$(GOPACKAGE) go run github.com/cilium/ebpf/cmd/bpf2go -output-dir ${OUTPUT_DIR} -output-stem "${OUTPUT_STEM}" -type execve_event -type connect_event -type connect_latency_event -type destroy_connection_event -type tcp_retransmission_event -type tcp_retransmission_synack_event -type tcp_set_state_event -type tcp_error_event -type tcp_reset_event -type tcp_icmp_error_event -type packet_drop_event -type file_open_event -target "${TARGET}" bpf "${BPF_SOURCE}" -- $(BPF_INCLUDES)
	sed --in-place --regexp-extended -e 's/loadBpf\(/LoadBpf(/g' -e 's/loadBpfObjects\(/LoadBpfObjects(/g' -e 's/(bpf(Objects|Programs|Maps|Specs|ProgramSpecs|MapSpecs|Variables|VariableSpecs))\b/Bpf\2/g' -e 's/^(type|func) ([a-z])/\1 \U\2\E/g' ${OUTPUT_DIR}/${OUTPUT_STEM}_${TARGET}.go

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BINARY) ./cmd/tracing_service

test:
	go test ./...

fmt:
	gofmt -w .

vet:
	go vet ./...

image:
	podman build -t $(IMAGE) .

# What is published is built from releases of my modules, never from a commit under test (a
# pseudo-version): https://wiki.vvvp.se/?page=go-module-versions. GOWORK=off reads the module graph the
# image is built from, and a failing go list fails the guard rather than passing it. A replaced module
# is checked as what replaces it: a directory in the repo has no version, and a replace onto a
# pseudo-version is caught.
guard-release-versions:
	@modules=$$(GOWORK=off go list -m -f '{{with .Replace}}{{.Path}} {{.Version}}{{else}}{{.Path}} {{.Version}}{{end}}' all) && \
	test_versions=$$(printf '%s\n' "$$modules" | grep -E '^github\.com/(Motmedel|altshiftab|vphpersson|intilgroup)/[^ ]* v[^ ]*[0-9]{14}-[0-9a-f]{12}$$' || true) && \
	if [ -n "$$test_versions" ]; then printf '[deploy] Built from test versions of my modules; release them first:\n%s\n' "$$test_versions" >&2; exit 1; fi

publish: guard-release-versions image
	podman tag $(IMAGE) $(REGISTRY)/$(IMAGE)
	podman push $(REGISTRY)/$(IMAGE)

clean:
	rm -f $(BINARY)
	rm -f ${OUTPUT_DIR}/${OUTPUT_STEM}_${TARGET}.go ${OUTPUT_DIR}/${OUTPUT_STEM}_${TARGET}.o
