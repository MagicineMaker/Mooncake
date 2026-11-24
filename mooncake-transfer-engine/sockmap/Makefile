# Userspace helper and BPF object for the single-host TCP replay.
OUT ?= build
CLANG ?= clang
MULTIARCH := $(shell $(CC) -print-multiarch)
CFLAGS ?= -O2 -g -Wall -Wextra

all: $(OUT)/redirect.bpf.o $(OUT)/sockmap_ctl

$(OUT):
	mkdir -p "$@"

$(OUT)/redirect.bpf.o: redirect.bpf.c | $(OUT)
	$(CLANG) -target bpf -O2 -g -I/usr/include/$(MULTIARCH) -c "$<" -o "$@"

$(OUT)/sockmap_ctl: sockmap_ctl.c | $(OUT)
	$(CC) $(CPPFLAGS) $(CFLAGS) "$<" -o "$@" $(LDFLAGS) -lbpf

.PHONY: all
