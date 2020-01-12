SRC_DIR ?= .
OUT_DIR ?= ./build

headers := $(SRC_DIR)/libkambp.h  $(SRC_DIR)/kambpf.h  $(SRC_DIR)/kambpf_user.h
srcfile := $(SRC_DIR)/libkambpf.c

$(OUT_DIR)/libkambpf.o: $(srcfile) $(header)
	mkdir -p $(OUT_DIR)
	gcc -o $@ -c $(srcfile)

clean:
	rm -rf $(OUT_DIR)

