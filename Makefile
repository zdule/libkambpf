S ?= .
B ?= ./build

srcfile := $(S)/libkambpf.c

$(B)/libkambpf.dll: $(B)/libkambpf.o
	gcc -shared -fPIC -o $@ $<

$(B)/libkambpf.o: $(srcfile) | $(B)
	gcc -o $@ -fPIC -c $<

$(B):
	mkdir -p $@


