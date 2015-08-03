PROGS = aesfile
OBJS  = aesfile.o
FLAGS = -lcrypto -w
CC    = gcc

%.o: %.c
	$(CC) -c $^ ${FLAGS}

aesfile: ${OBJS}
	$(CC) -o $@ ${OBJS} ${FLAGS}

clean:
	$(RM) $(PROGS) $(wildcard *.h.gch) $(wildcard *.o)
