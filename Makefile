# Variables
CC=gcc
LDFLAGS= -lpcap
CFLAGS= -Wall 
OUT=trc
LIBS=
RM= rm -fr

# Compile all c files
SRC= $(wildcard *.c)
#OBJ= $(SRC: .c=.o)

all: dispatcher.o main.o
	$(CC) $^ $(LDFLAGS) -o $(OUT)

clean:
	$(RM) *.o

veryclean: clean
	$(RM) $(OUT) 
