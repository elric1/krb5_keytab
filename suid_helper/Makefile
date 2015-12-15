#
#

WFLAGS=		-Werror
WFLAGS+=	-Wall -Wextra -Wstrict-prototypes -Wmissing-prototypes
WFLAGS+=	-Wpointer-arith -Wno-traditional -Wreturn-type -Wswitch
WFLAGS+=	-Wno-shadow -Wwrite-strings -Wno-unused-parameter
WFLAGS+=	-Wsign-compare

all: krb5_keytab

clean:
	rm -f krb5_keytab

krb5_keytab: krb5_keytab.c
	$(CC) $(CFLAGS) $(WFLAGS) -o krb5_keytab krb5_keytab.c
