S ?= .
B ?= ./build

.PHONY: libkambpf

libkambpf: $B/libkambpf.so $B/libkambpf.o

srcfile := $(S)/libkambpf.c

$(B)/libkambpf.so: $(B)/libkambpf.o
	gcc -shared -fPIC -o $@ $<

$(B)/libkambpf.o: $(srcfile) | $(B)
	gcc -o $@ -fPIC -c $<

$(B):
	mkdir -p $@


