# Makefile for shareacl BOF
#
# Builds x64 and x86 object files suitable for Cobalt Strike inline execution.
# Requires the mingw-w64 toolchain:
#   apt install mingw-w64   (Debian/Ubuntu)
#   brew install mingw-w64  (macOS)
#
# Safe-use: compile only. Deployment is restricted to authorized engagements.

CC_X64 = x86_64-w64-mingw32-gcc
CC_X86 = i686-w64-mingw32-gcc

CFLAGS  = -c -Os -fno-asynchronous-unwind-tables -nostdlib
CFLAGS += -fno-ident -fpack-struct=8 -falign-functions=1
CFLAGS += -ffunction-sections -fdata-sections -fno-exceptions
CFLAGS += -I.

all: shareacl.x64.o shareacl.x86.o

shareacl.x64.o: shareacl.c beacon.h
	$(CC_X64) $(CFLAGS) -o $@ $<

shareacl.x86.o: shareacl.c beacon.h
	$(CC_X86) $(CFLAGS) -o $@ $<

clean:
	rm -f shareacl.x64.o shareacl.x86.o

.PHONY: all clean
