AC				= as
AFLAGS			= --32

SHELLCODE_NAME=shellcode

SRC=$(SHELLCODE_NAME).s
OBJ=$(SRC:%.s=%.o)
OBJ_DUMP=$(OBJ:%.o=%.dump)
OBJ_BASE64=$(OBJ_DUMP:%.dump=%.base64)

all: $(OBJ) $(OBJ_DUMP) $(OBJ_BASE64)
.PHONY: all

clean:
	rm -f $(OBJ) $(OBJ_DUMP) $(OBJ_BASE64)
.PHONY: clean

re: clean all
.PHONY: re

%.base64: %.dump
	base64 $< > $@

%.dump: %.o
	objcopy -O binary -j .text $< $@

%.o: %.s
	$(AC) $(AFLAGS) $< -o $@
