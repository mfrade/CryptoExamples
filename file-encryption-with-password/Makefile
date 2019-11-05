CC     = gcc
LIBS   = -lsodium -lbsd
CFLAGS = -Wall -g -D SHOW_DEBUG
IFLAGS = -kr -cli4

PROGRAM = file-encryption

all: debug.o ${PROGRAM}

${PROGRAM}: ${PROGRAM}.o debug.o
	${CC} ${CFLAGS} -o ${PROGRAM} ${PROGRAM}.o debug.o ${LIBS}

${PROGRAM}.o: ${PROGRAM}.c
	${CC} ${CFLAGS} -c ${PROGRAM}.c

debug.o: debug.c debug.h
	${CC} ${CFLAGS} -c debug.c

doc:
	doxygen Doxyfile


indent:
	dos2unix *.c *.h
	indent ${IFLAGS} *.c *.h


clean:
	rm -f *.o core ${PROGRAM} *~
	rm -f -R html

