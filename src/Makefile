CXX = g++

#  -g          compile with debug information
#  -Wall       give all diagnostic warnings
#  -pedantic   require compliance with ANSI standard
#  -O0         do not optimize generated code
CPPFLAGS = -Wall -pedantic -std=c++14 -Iinclude

# -lm        link to libm (math library)
# -lcrypto   link to crypto library
# -lssl      link to openssl library
# -lpthread  link to pthread library
LDFLAGS = -lm -lcrypto -lssl -lpthread -lgcov

PROGRAMS = initialize.cc sign.cc verify.cc test.cc
EXTRAS = crypto_utils.cc treehash.cc types.cc wots.cc
HEADERS = $(EXTRAS:.cc=.hh) $(PROGRAMS:.cc=.hh)
SOURCES = $(PROGRAMS) $(EXTRAS)
OBJECTS = $(SOURCES:.cc=.o)
TARGETS = $(PROGRAMS:.cc=)

debug:      CPPFLAGS    += -g -O0
release:    CPPFLAGS    += -O3
profile:	CPPFLAGS	+= -pg -O3
coverage:	CPPFLAGS	+= -g -fprofile-arcs -ftest-coverage

all: hardyhash test

debug:      hardyhash
release:    hardyhash
profile:    hardyhash
coverage:	test

hardyhash: hardyhash.o types.o initialize.o sign.o verify.o crypto_utils.o treehash.o wots.o
	$(CXX) $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

test: test.o types.o initialize.o sign.o verify.o crypto_utils.o treehash.o wots.o
	$(CXX) $(CPPFLAGS) -o $@ $^ $(LDFLAGS)

Makefile.dependencies:: $(SOURCES) $(HEADERS)
	$(CXX) $(CPPFLAGS) -MM $(SOURCES) > Makefile.dependencies

-include Makefile.dependencies

.PHONY: clean

clean:
	@rm -f $(TARGETS) $(OBJECTS) core Makefile.dependencies