# Rebuild the committed CO-RE object after editing bpf/monitor.bpf.c.
#
# Needs clang, llvm, and bpftool on a Linux host with BTF
# (/sys/kernel/btf/vmlinux). The resulting monitor.bpf.o is committed and
# go:embed'd, so end users need none of this — `go install` stays toolchain-free.
# CI (E5) rebuilds and fails if the committed object is stale.

CLANG ?= clang

monitor.bpf.o: bpf/monitor.bpf.c bpf/vmlinux.h
	$(CLANG) -O2 -g -target bpf -D__TARGET_ARCH_x86 -Ibpf -c bpf/monitor.bpf.c -o $@

bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

.PHONY: clean
clean:
	rm -f bpf/vmlinux.h
