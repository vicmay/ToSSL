CC = gcc
CFLAGS = -fPIC -O2 -Wall -I/usr/include/tcl -I/usr/include -I/usr/local/include
# Add OpenSSL 3.x specific flags
CFLAGS += -DOPENSSL_API_COMPAT=0x30000000L
CFLAGS += -DOPENSSL_NO_DEPRECATED
LDFLAGS = -shared -lssl -lcrypto
TARGET = libtossl.so

# Source files for modular build
SRC_MODULAR = tossl_main.c tossl_core.c tossl_keys.c tossl_rsa.c tossl_dsa.c tossl_ec.c tossl_ed25519.c tossl_x509.c tossl_legacy.c tossl_pbe.c tossl_keywrap.c tossl_sm2.c tossl_ed448.c tossl_x448.c tossl_csr.c tossl_pkcs7.c tossl_pkcs12.c tossl_ocsp.c tossl_crl.c tossl_ca.c tossl_ssl.c tossl_modern.c

# Original single file build (kept for reference)
SRC_ORIGINAL = tossl.c

# Default target builds modular version
all: modular

# Build modular version
modular: $(TARGET)

$(TARGET): $(SRC_MODULAR) tossl.h
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC_MODULAR) $(LDFLAGS)

# Build original single file version
original: $(SRC_ORIGINAL)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC_ORIGINAL) $(LDFLAGS)

clean:
	rm -f $(TARGET)

# Development targets
debug: CFLAGS += -g -DDEBUG
debug: modular

# Install target
install: modular
	cp $(TARGET) /usr/local/lib/
	cp pkgIndex.tcl /usr/local/lib/

# Uninstall target
uninstall:
	rm -f /usr/local/lib/$(TARGET)
	rm -f /usr/local/lib/pkgIndex.tcl

# Test target
test: modular
	tclsh test_tossl_basic.tcl

# Help target
help:
	@echo "Available targets:"
	@echo "  all/modular  - Build modular version (default)"
	@echo "  original     - Build original single file version"
	@echo "  debug        - Build with debug symbols"
	@echo "  clean        - Remove built files"
	@echo "  install      - Install to system"
	@echo "  uninstall    - Remove from system"
	@echo "  test         - Run basic tests"
	@echo "  help         - Show this help"
