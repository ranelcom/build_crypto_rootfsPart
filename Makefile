CC=gcc
CFLAGS= -c -Wall
OBJECTS= lobby.o

all: crypt

crypt: $(OBJECTS)
	$(CC) $(OBJECTS) -o crypt -lcryptsetup

%.o: %.cc
	$(CC) $(CFLAGS) $<
	
clean:
	rm -rf *.o

clean_all:
	rm -rf *.o crypt
