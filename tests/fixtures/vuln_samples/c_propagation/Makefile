CC ?= gcc
CFLAGS ?= -g -O0 -Wall -fsanitize=address,undefined
LDFLAGS ?= -fsanitize=address,undefined

SOURCES := src/codec_a.c src/codec_b.c src/codec_c.c

all: libcodec.a

libcodec.a: $(SOURCES:.c=.o)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f src/*.o libcodec.a
