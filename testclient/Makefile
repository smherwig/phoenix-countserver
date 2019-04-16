STATIC_LIBS= $(addprefix $(HOME)/lib/, librpc.a librho.a)

#CFLAGS= -Wall -Werror -Wextra -DRHO_DEBUG -DRHO_TRACE
LDFLAGS= $(STATIC_LIBS) -lssl -lcrypto -lpthread

OBJS = tcadserver.o tcadclient.o

all: tcadserver tcadclient

tcadserver: tcadserver.o
	$(CC) -o $@ $^ $(HOME)/lib/librpc.a $(HOME)/lib/librho.a -lssl -lcrypto -lpthread

tcadserver.o: tcadserver.c tcad.h
	$(CC) -c -o $@ -Wall -Werror -Wextra -I$(HOME)/include $<

tcadclient: tcadclient.o
	$(CC) -o $@ $^ $(HOME)/lib/librho.a $(HOME)/lib/libbearssl.a

tcadclient.o: tcadclient.c tcad.h
	$(CC) -c -o $@ -Wall -Werror -Wextra -I$(HOME)/include $<

clean:
	rm -f tcadserver tcadclient $(OBJS)

.PHONY: clean
