CC=gcc
LDFLAGS=-shared -lruby1.8 /usr/local/lib/libdistorm3.so
CFLAGS=-ggdb -Wall -DSUPPORT_64BIT_OFFSET -I/usr/lib/ruby/1.8/i486-linux/
OBJECTS=../src/frasm.o

frasm: $(OBJECTS)
	@$(CC) $(OBJECTS) $(CCFLAGS) -o frasm.so $(LDFLAGS)

install:
	@cp -p frasm.so /usr/local/lib

clean:
	@echo " "
	rm -f ../src/*~
	rm -f ../src/core
	rm -f ../src/*.o
	rm -f ../src/*.so
	rm -f *.so
