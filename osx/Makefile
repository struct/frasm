CC=gcc
LDFLAGS=-bundle -undefined suppress -flat_namespace -lruby /usr/local/lib/libdistorm64.dylib
CFLAGS=-ggdb -Wall -DSUPPORT_64BIT_OFFSET -I/opt/local/lib/ruby/1.8/i686-darwin9/
OBJECTS=../src/frasm.o

frasm: $(OBJECTS)
	@$(CC) $(OBJECTS) $(CCFLAGS) -o frasm.bundle $(LDFLAGS)

install:
	@cp -p frasm.bundle /usr/local/lib

clean:
	@echo " "
	rm -f ../src/*~
	rm -f ../src/core
	rm -f ../src/*.o
	rm -f ../src/*.so
	rm -f *.bundle
