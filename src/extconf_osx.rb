require 'mkmf'
$LDFLAGS << '-bundle -undefined suppress -flat_namespace -lruby /usr/local/lib/libdistorm3.dylib'
create_makefile('frasm')
