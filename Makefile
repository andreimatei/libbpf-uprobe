LIBBPF_OBJ := libbpf.a
OUTPUT := build
# The bcc dir is where `make` in `bcc/libbpf-tools` puts the libbpf headers. Including the output
# dir is needed for the skel.h file.

CLANG ?= /home/andrei/llvm/bin/clang
LLVM_STRIP ?= /home/andrei/llvm/bin/llvm-strip
BPFTOOL ?= /home/andrei/work/src/github.com/iovisor/bcc/libbpf-tools/bin/bpftool
# libbpf headers, as distributed by bcc (needs a make in the libbpf-tools dir)
LIBBPF ?= /home/andrei/work/src/github.com/iovisor/bcc/libbpf-tools/.output

INCLUDES := -I$(LIBBPF) -I$(OUTPUT) 

$(OUTPUT)/uprobe: $(OUTPUT)/uprobe.o 
	$(CC) $(OUTPUT)/uprobe.o $(LIBBPF_OBJ) -lelf -lz -o $(OUTPUT)/uprobe

$(OUTPUT):
	mkdir -p $@

$(OUTPUT)/uprobe.o: uprobe.c $(OUTPUT)/uprobe.skel.h
	$(CC) $(INCLUDES) -Wall -c -o $(OUTPUT)/uprobe.o uprobe.c

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(BPFTOOL) gen skeleton $< > $@

# I got vmlinux.h from bcc.
$(OUTPUT)/%.bpf.o: %.bpf.c  vmlinux.h $(wildcard %.h) | $(OUTPUT)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86	        \
		     $(INCLUDES) -c $(filter %.c,$^) -o $@ &&		      \
	$(LLVM_STRIP) -g $@

