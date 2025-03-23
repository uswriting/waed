CC = clang
CFLAGS = -Wall -Wextra -std=c2x -O3 -flto -fdata-sections -ffunction-sections -fno-stack-protector -fomit-frame-pointer -DNDEBUG
LDFLAGS =

# Detect OS for platform-specific flags
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS specific flags
    LDFLAGS += -Wl,-dead_strip
else
    # Linux specific flags
    LDFLAGS += -Wl,--gc-sections -Wl,--strip-all -Wl,-z,norelro
endif

LDLIBS =

# Default version if git is not available
DEFAULT_VERSION = 1.0.0

all: waed

# Force rebuild of version.h every time by making it a .PHONY target
.PHONY: version.h

version.h:
	@echo "#ifndef VERSION_H" > version.h
	@echo "#define VERSION_H" >> version.h
	@if git describe --tags 2>/dev/null; then \
		echo "#define TOOL_VERSION \"$(shell git describe --tags 2>/dev/null || echo $(DEFAULT_VERSION))\"" >> version.h; \
	else \
		echo "#define TOOL_VERSION \"$(DEFAULT_VERSION)\"" >> version.h; \
	fi
	@echo "#endif /* VERSION_H */" >> version.h

waed: cli.c waed.c waed.h version.h
	$(CC) $(CFLAGS) cli.c waed.c -o waed $(LDFLAGS) $(LDLIBS)
	strip waed

clean:
	rm -f waed version.h

install: waed
	install -m 755 waed /usr/local/bin/

.PHONY: all clean install