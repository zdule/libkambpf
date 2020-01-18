SRC_DIR ?= .
BUILD_DIR ?= ./build

headers := $(SRC_DIR)/libkambp.h  $(SRC_DIR)/kambpf.h  $(SRC_DIR)/kambpf_user.h
srcfile := $(SRC_DIR)/libkambpf.c

$(BUILD_DIR)/libkambpf.o: $(srcfile) $(header) | $(BUILD_DIR)
	gcc -o $@ -c $<

$(BUILD_DIR):
	mkdir -p $@


