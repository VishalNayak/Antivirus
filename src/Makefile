CC=gcc
CFLAGS=-O0 -std=c99 -Wall -Werror -I../include -fPIC -g3 
OPTS=`pkg-config --cflags --libs libnotify`
LDFLAGS=-lcrypto -lcurl

SRCS:=$(shell find . -name \*.c)

.PHONY: antivirus clean kmodule

antivirus: $(SRCS:%.c=%.o) 
	$(CC) -o ../$@ $^ $(LDFLAGS) $(OPTS)

%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(OPTS) -o $@ $^ 

clean:
	rm -rf obj *.o ../antivirus .*.swp binary/*.o
