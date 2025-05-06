CC = gcc
CFLAGS = -fPIC -O2 -Wall -I/usr/include/tcl -I/usr/include -I/usr/local/include
LDFLAGS = -shared -lssl -lcrypto
TARGET = libopentssl.so
SRC = opentssl.c

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)
