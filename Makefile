CC=gcc
CFLAGS= -c -Wall
OBJECTS= lobby.o
LIBS = -lcryptsetup
PROGRAM_NAME = crypt

all: crypt

crypt: $(OBJECTS)
	$(CC) $(OBJECTS) -o $(PROGRAM_NAME) $(LIBS)

%.o: %.cc
	$(CC) $(CFLAGS) $<
	
clean:
	rm -rf *.o

clean_all:
	rm -rf *.o crypt
