PROGS = dirhash
OBJS  = dirhash.o stack.o
FLAGS = -lcrypto -w
CC    = gcc

%.o: %.c %.h
	$(CC) -c $^ ${FLAGS}

dirhash: ${OBJS}
	$(CC) -o $@ ${OBJS} ${FLAGS}

clean:
	$(RM) $(OBJS) $(PROGS) $(wildcard *.h.gch) $(wildcard *.o)
