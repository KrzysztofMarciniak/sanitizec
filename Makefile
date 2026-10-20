CC ?= cc
PREFIX ?= /usr/local
CFLAGS ?= -Wall -Wextra
OPTFLAGS ?= -O3
ARCHFLAGS ?=
THREAD_FLAGS ?= -pthread
CPPFLAGS ?= -I.
CACHE ?= 0

LIB_NAME := sanitizec
LIBRARY := lib$(LIB_NAME).so
COMPILE_FLAGS := $(CPPFLAGS) $(OPTFLAGS) $(ARCHFLAGS) $(CFLAGS) -fPIC $(THREAD_FLAGS)
BUILD_CONFIG := .sanitizec-build-config
MISC_SOURCES := $(wildcard misc/*.c)
ifeq ($(CACHE),1)
COMPILE_FLAGS += -DSANITIZEC_ENABLE_CACHE
else
MISC_SOURCES := $(filter-out misc/sanitizec_cache.c,$(MISC_SOURCES))
endif
LIB_SOURCES := $(filter-out test.c,$(wildcard *.c)) \
               $(MISC_SOURCES) $(wildcard rules/*/*.c)
TEST_SOURCES := test.c $(wildcard tests/*/*.c)
LIB_OBJECTS := $(LIB_SOURCES:.c=.o)
TEST_OBJECTS := $(TEST_SOURCES:.c=.o)

.PHONY: all test check benchmark clean install
.PHONY: FORCE

all: $(LIBRARY)

$(LIBRARY): $(LIB_OBJECTS)
	$(CC) -shared $(LDFLAGS) $(THREAD_FLAGS) -o $@ $^ $(LDLIBS)

$(BUILD_CONFIG): FORCE
	@printf '%s\n' '$(CC)' '$(COMPILE_FLAGS)' '$(LDFLAGS)' '$(LDLIBS)' > $@.tmp
	@if ! cmp -s $@.tmp $@; then mv $@.tmp $@; else rm $@.tmp; fi

%.o: %.c $(BUILD_CONFIG)
	$(CC) $(COMPILE_FLAGS) -c -o $@ $<

test: test-runner

test-runner: $(TEST_OBJECTS) $(LIBRARY)
	$(CC) $(LDFLAGS) $(THREAD_FLAGS) -o $@ $(TEST_OBJECTS) -L. -l$(LIB_NAME) \
		-Wl,-rpath,'$$ORIGIN' $(LDLIBS)

check: test-runner
	./test-runner

bench-runner: bench/benchmark.c $(LIBRARY) $(BUILD_CONFIG)
	$(CC) $(COMPILE_FLAGS) $(LDFLAGS) -o $@ $< -L. -l$(LIB_NAME) \
		-Wl,-rpath,'$$ORIGIN' $(THREAD_FLAGS) $(LDLIBS)

benchmark: bench-runner
	./bench-runner

clean:
	$(RM) $(LIB_OBJECTS) $(TEST_OBJECTS) $(LIBRARY) test-runner \
		bench-runner misc/sanitizec_cache.o $(BUILD_CONFIG) \
		$(BUILD_CONFIG).tmp

install: $(LIBRARY)
	install -Dm644 $(LIBRARY) $(DESTDIR)$(PREFIX)/lib/$(LIBRARY)
	install -Dm644 $(LIB_NAME).h $(DESTDIR)$(PREFIX)/include/$(LIB_NAME).h
