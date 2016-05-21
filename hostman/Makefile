CC = gcc
CFLAGS = -Wall
LDFLAGS = 

SOURCES = $(wildcard src/*.c) #$(wildcard src/*.h)
OBJECTS = $(patsubst src/%.c, obj/%.o, $(SOURCES))
CLEAROBJECTS = $(wildcard obj/*.o)
 
EXECUTABLE = hostman
STRIP=/usr/bin/strip

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^
	$(STRIP) $(EXECUTABLE)

obj/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -rf $(CLEAROBJECTS)
