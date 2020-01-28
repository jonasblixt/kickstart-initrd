bin_PROGRAMS = kickstart-initrd

kickstart_initrd_SOURCES  = main.c \
                            keystore.c \
                            dm.c \
                            gpt.c \
                            kcapi/kcapi-kernel-if.c \
                            kcapi/kcapi-utils.c \
                            kcapi/kcapi-md.c \
                            kcapi/kcapi-asym.c

kickstart_initrd_CFLAGS  = $(CODE_COVERAGE_CFLAGS) \
                           $(BPAK_CFLAGS)

kickstart_initrd_LDFLAGS = -all-static
kickstart_initrd_LDADD = $(BPAK_LIBS)

kickstart_initrd_LIBS = $(CODE_COVERAGE_LIBS)


