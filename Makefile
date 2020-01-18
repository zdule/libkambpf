S ?= .
B ?= ./build

srcfile := $(S)/libkambpf.c

$(B)/libkambpf.o: $(srcfile) | $(B)
	gcc -o $@ -c $<

$(B):
	mkdir -p $@


