CC = gcc
CFLAGS = -lnet -lpcap -pthread
SRCS = server.c client.c

all: server client

server: server.c
	$(CC) $(CFLAGS) server.c -o server

client: client.c
	$(CC) $(CFLAGS) client.c -o client

clean:
	rm -f *.o
	rm -f client
	rm -f server
