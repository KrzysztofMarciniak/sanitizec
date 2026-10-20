CC ?= cc
PREFIX ?= /usr/local
CFLAGS ?= -Wall -Wextra
CFLAGS += -fPIC
CPPFLAGS ?= -I.

LIB_NAME := sanitizec
LIBRARY := lib$(LIB_NAME).so
LIB_SOURCES := $(filter-out test.c,$(wildcard *.c)) \
               $(wildcard misc/*.c rules/*/*.c)
TEST_SOURCES := test.c $(wildcard tests/*/*.c)
LIB_OBJECTS := $(LIB_SOURCES:.c=.o)
TEST_OBJECTS := $(TEST_SOURCES:.c=.o)

.PHONY: all test check clean install

all: $(LIBRARY)

$(LIBRARY): $(LIB_OBJECTS)
	$(CC) -shared $(LDFLAGS) -o $@ $^ $(LDLIBS)

test: test-runner

test-runner: $(TEST_OBJECTS) $(LIBRARY)
	$(CC) $(LDFLAGS) -o $@ $(TEST_OBJECTS) -L. -l$(LIB_NAME) \
		-Wl,-rpath,'$$ORIGIN' $(LDLIBS)

check: test-runner
	./test-runner

clean:
	$(RM) $(LIB_OBJECTS) $(TEST_OBJECTS) $(LIBRARY) test-runner

install: $(LIBRARY)
	install -Dm644 $(LIBRARY) $(DESTDIR)$(PREFIX)/lib/$(LIBRARY)
	install -Dm644 $(LIB_NAME).h $(DESTDIR)$(PREFIX)/include/$(LIB_NAME).h
