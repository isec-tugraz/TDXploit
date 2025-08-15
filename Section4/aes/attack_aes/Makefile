all: aes_spy_flush_flush_first_round_tdx aes_spy_flush_flush_last_round_tdx aes_spy_flush_flush
openssl:
	git clone https://github.com/openssl/openssl
	cd openssl
	git checkout origin/OpenSSL_1_0_2-stable
	sed -i '0,/prefetch/{s/#if 1/#if 0/}' crypto/aes/aes_x86core.c
	./config -d shared no-asm no-hw
	make -j build_libcrypto
aes_%: aes_%.cpp
	g++ -std=gnu++11 -O2 -o $@ $< -Iopenssl -L./openssl -I. -L./ -lcrypto -pthread
