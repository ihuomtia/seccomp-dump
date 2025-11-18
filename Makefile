CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = seccomp-dump
SRC = seccomp.c

all: $(TARGET)

$(TARGET): $(SRC) syscalls.h
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

.PHONY: all clean install uninstall
