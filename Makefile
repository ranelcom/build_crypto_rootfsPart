CC=gcc
CFLAGS= -c -Wall
OBJECTS= lobby.o
LIBS = -lcryptsetup

all: crypt

crypt: $(OBJECTS)
	$(CC) $(OBJECTS) -o crypt $(LIBS)

%.o: %.cc
	$(CC) $(CFLAGS) $<
	
clean:
	rm -rf *.o

clean_all:
	rm -rf *.o crypt
