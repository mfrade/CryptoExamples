CC     = gcc
LIBS   = -lsodium -lbsd
CFLAGS = -Wall -g -D SHOW_DEBUG
IFLAGS = -kr -cli4

ARGS = args
PROGRAM = file-encryption

all: ${PROGRAM}

${PROGRAM}: debug.o cmdline.o ${PROGRAM}.o
	${CC} ${CFLAGS} -o ${PROGRAM} debug.o cmdline.o ${PROGRAM}.o ${LIBS}

${PROGRAM}.o: ${PROGRAM}.c
	${CC} ${CFLAGS} -c ${PROGRAM}.c

cmdline.o: cmdline.c cmdline.h
	${CC} ${CFLAGS} -Wno-unused-but-set-variable -c cmdline.c

debug.o: debug.c debug.h
	${CC} ${CFLAGS} -c debug.c

cmdline.c cmdline.h: $(ARGS).ggo
	gengetopt -i $(ARGS).ggo

doc:
	doxygen Doxyfile


indent:
	dos2unix *.c *.h
	indent ${IFLAGS} *.c *.h


clean:
	rm -f *.o core ${PROGRAM} *~
	rm -f -R html

