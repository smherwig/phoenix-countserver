OBJS = tcadserver.o

all: tcadserver

tcadserver: tcadserver.o
	$(CC) -o $@ $^ $(HOME)/lib/librpc.a $(HOME)/lib/librho.a -lssl -lcrypto -lpthread

tcadserver.o: tcadserver.c ../common/tcad.h
	$(CC) -c -o $@ -Wall -Werror -Wextra -I../common -I$(HOME)/include $<

clean:
	rm -f tcadserver $(OBJS)

.PHONY: clean
