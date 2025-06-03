lib := libfs.a
objs := fs.o disk.o
CC := gcc
CFLAGS := -Wall -Wextra -Werror -g
AR := ar
ARFLAGS := rcs

ifneq ($(V),1)
Q = @
endif

all: $(lib)

$(lib): $(objs)
	@echo "AR $@"
	$(Q)$(AR) $(ARFLAGS) $@ $^

%.o: %.c
	@echo "CC $@"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

# Dependency tracking
deps := $(patsubst %.o,%.d,$(objs))
-include $(deps)

clean:
	@echo "clean"
	$(Q)rm -f $(lib) $(objs) $(deps)
