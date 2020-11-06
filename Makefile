#   This file is part of the libkambpf library (https://github.com/zdule/libkambpf).
#   It is file is offered under two licenses GPLv2 and Apache License Version 2.
#   For more information see the LICENSE file at the root of the library.
#
#   Copyright 2020 Dusan Zivanovic

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


