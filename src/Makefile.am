bin_PROGRAMS = kickstart-initrd

kickstart_initrd_SOURCES  = main.c \
                            ini.c \
                            config.c \
                            log.c \
                            utils.c \
                            keystore.c \
                            dm.c \
                            gpt.c \
                            keys.c \
                            ks_mbedtls.c

kickstart_initrd_SOURCES += uuid/clear.c \
                            uuid/compare.c \
                            uuid/copy.c \
                            uuid/isnull.c \
                            uuid/pack.c \
                            uuid/parse.c \
                            uuid/unpack.c \
                            uuid/unparse.c

kickstart_initrd_SOURCES += mbedtls/library/pk.c \
                            mbedtls/library/pem.c \
                            mbedtls/library/error.c \
                            mbedtls/library/rsa.c \
                            mbedtls/library/rsa_internal.c \
                            mbedtls/library/ecdsa.c \
                            mbedtls/library/platform.c \
                            mbedtls/library/platform_util.c \
                            mbedtls/library/asn1parse.c \
                            mbedtls/library/asn1write.c \
                            mbedtls/library/bignum.c \
                            mbedtls/library/ecp.c \
                            mbedtls/library/ecp_curves.c \
                            mbedtls/library/hmac_drbg.c \
                            mbedtls/library/md.c \
                            mbedtls/library/sha256.c \
                            mbedtls/library/ripemd160.c \
                            mbedtls/library/md5.c \
                            mbedtls/library/sha1.c \
                            mbedtls/library/base64.c \
                            mbedtls/library/oid.c \
                            mbedtls/library/pk_wrap.c \
                            mbedtls/library/pkparse.c \
                            mbedtls/library/pkcs12.c \
                            mbedtls/library/cipher.c \
                            mbedtls/library/gcm.c \
                            mbedtls/library/aesni.c \
                            mbedtls/library/ccm.c \
                            mbedtls/library/chachapoly.c \
                            mbedtls/library/poly1305.c \
                            mbedtls/library/chacha20.c \
                            mbedtls/library/cipher_wrap.c \
                            mbedtls/library/aes.c \
                            mbedtls/library/arc4.c \
                            mbedtls/library/blowfish.c \
                            mbedtls/library/camellia.c \
                            mbedtls/library/des.c \
                            mbedtls/library/entropy.c \
                            mbedtls/library/pkwrite.c \
                            mbedtls/library/ctr_drbg.c \
                            mbedtls/library/pkcs5.c \
                            mbedtls/library/entropy_poll.c \
                            mbedtls/library/timing.c

kickstart_initrd_CFLAGS  = $(CODE_COVERAGE_CFLAGS) \
                           $(BPAK_CFLAGS) \
                           -I$(top_srcdir)/src/mbedtls/include \
                           -I$(top_srcdir)/src/uuid

kickstart_initrd_LDFLAGS = -all-static
kickstart_initrd_LDADD = $(BPAK_LIBS)

kickstart_initrd_LIBS = $(CODE_COVERAGE_LIBS)


