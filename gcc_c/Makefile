CC=gcc
CFLAGS=-Wall -Wextra -O2
SRCDIR=.
BINDIR=bin
SOURCES=$(wildcard $(SRCDIR)/*.c) ../ntlib/ntlib.c
OBJECTS=$(patsubst $(SRCDIR)/%.c, $(BINDIR)/%.o, $(SOURCES))
EXECUTABLE=main

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $^

$(BINDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $^

.PHONY :clean
clean:  
#Windows
	del bin\main.o
	del main.exe