CC=gcc
lDFLAGS=
CFLAGS= -c -Wall
OUT=trc
LIBS=
RM= rm -fr
SRC= $(wildcard *.c)
OBJ= $(SRC: .c=.o)

all: $(OBJ)
	$(CC) $^ $(LDFLAGS) -o $(OUT)


clean:
	$(RM) *.o

veryclean: clean
	$(RM) $(OUT) 
