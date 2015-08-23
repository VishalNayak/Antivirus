SRCS:=$(shell find . -name \*.c)

.PHONY: all direc clean

#all: $(patsubst %.c,%,$(SRCS))
all: $(basename $(SRCS))

%:%.c direc 
	gcc -o ../bin/$@ $<

direc:
	mkdir -p ../bin

clean:
	rm -rf ../bin/open* 
