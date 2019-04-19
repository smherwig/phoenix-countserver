OBJS = tcadclient.o serverless.o

all: tcadclient serverless

tcadclient: tcadclient.o
	$(CC) -o $@ $^ $(HOME)/lib/librpc.a $(HOME)/lib/librho.a \
		$(HOME)/lib/libbearssl.a

tcadclient.o: tcadclient.c ../common/tcad.h
	$(CC) -c -o $@ -Wall -Werror -Wextra -I../common -I$(HOME)/include $<

serverless: serverless.o
	$(CC) -o $@ $^ $(HOME)/lib/librho.a $(HOME)/lib/libbearssl.a

serverless.o: serverless.c
	$(CC) -c -o $@ -Wall -Werror -Wextra -I$(HOME)/include $^

clean:
	rm -f tcadclient servless $(OBJS)

.PHONY: clean all
