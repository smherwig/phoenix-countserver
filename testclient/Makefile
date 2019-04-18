OBJS = tcadclient.o

all: tcadclient

tcadclient: tcadclient.o
	$(CC) -o $@ $^ $(HOME)/lib/librpc.a $(HOME)/lib/librho.a \
		$(HOME)/lib/libbearssl.a

tcadclient.o: tcadclient.c ../common/tcad.h
	$(CC) -c -o $@ -Wall -Werror -Wextra -I../common -I$(HOME)/include $<

clean:
	rm -f tcadclient $(OBJS)

.PHONY: clean
