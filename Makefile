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
COMPILE_FLAGS := $(CPPFLAGS) $(OPTFLAGS) $(ARCHFLAGS) $(CFLAGS) -flto \
                 -fvisibility=hidden -fPIC $(THREAD_FLAGS)
LINK_FLAGS := $(LDFLAGS) -flto
BUILD_CONFIG := .sanitizec-build-config
PATTERN_HEADER := misc/sanitizec_patterns.generated.h
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
	$(CC) -shared $(LINK_FLAGS) $(THREAD_FLAGS) -o $@ $^ $(LDLIBS)

$(PATTERN_HEADER): tools/generate_patterns.py
	python3 $< $@

misc/sanitizec_pattern.o rules/sanitize_sql/sanitize_sql.o \
rules/sanitize_reverse_shell/sanitize_reverse_shell.o: $(PATTERN_HEADER)

$(BUILD_CONFIG): FORCE
	@printf '%s\n' '$(CC)' '$(COMPILE_FLAGS)' '$(LDFLAGS)' '$(LDLIBS)' > $@.tmp
	@if ! cmp -s $@.tmp $@; then mv $@.tmp $@; else rm $@.tmp; fi

%.o: %.c $(BUILD_CONFIG)
	$(CC) $(COMPILE_FLAGS) -c -o $@ $<

test: test-runner

test-runner: $(TEST_OBJECTS) misc/sanitizec_buffer.o $(LIBRARY)
	$(CC) $(LINK_FLAGS) $(THREAD_FLAGS) -o $@ $(TEST_OBJECTS) -L. -l$(LIB_NAME) \
		misc/sanitizec_buffer.o -Wl,-rpath,'$$ORIGIN' $(LDLIBS)

check: test-runner
	./test-runner

bench-runner: bench/benchmark.c $(LIBRARY) $(BUILD_CONFIG)
	$(CC) $(COMPILE_FLAGS) $(LINK_FLAGS) -o $@ $< -L. -l$(LIB_NAME) \
		-Wl,-rpath,'$$ORIGIN' $(THREAD_FLAGS) $(LDLIBS)

benchmark: bench-runner
	./bench-runner

clean:
	$(RM) $(LIB_OBJECTS) $(TEST_OBJECTS) $(LIBRARY) test-runner \
		bench-runner misc/sanitizec_cache.o $(BUILD_CONFIG) \
		$(BUILD_CONFIG).tmp $(PATTERN_HEADER)

install: $(LIBRARY)
	install -Dm644 $(LIBRARY) $(DESTDIR)$(PREFIX)/lib/$(LIBRARY)
	install -Dm644 $(LIB_NAME).h $(DESTDIR)$(PREFIX)/include/$(LIB_NAME).h
