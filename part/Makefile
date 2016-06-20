CC = gcc
CFLAGS = -g -w
SRCS = in.c out.c

all: in out

in: in.c
	$(CC) $(CFLAGS) in.c -o in -lpcap

out: out.c
	$(CC) $(CFLAGS) out.c -o out -lnet

clean:
	rm -f *.o
	rm -f in
	rm -f out
