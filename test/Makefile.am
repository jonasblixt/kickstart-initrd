COMMON_TEST_CFLAGS = -I $(top_srcdir)/src \
                     -fsanitize=address

check_LTLIBRARIES = libnala.la

libnala_la_SOURCES = nala.c

check_PROGRAMS = test_hello

test_hello_SOURCES = test_hello.c
test_hello_LDADD = libnala.la
test_hello_CFLAGS = $(COMMON_TEST_CFLAGS)

TESTS = test_hello
