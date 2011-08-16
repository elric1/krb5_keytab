#
#

PERL	?= /usr/bin/perl
DESTDIR	?= /usr

SBIN	 = $(DESTDIR)/sbin
MAN	 = $(DESTDIR)/share/man
MAN5	 = $(MAN)/man5
MAN8	 = $(MAN)/man8
EXAMPL	 = $(DESTDIR)/share/examples/krb5_keytab

CFLAGS	+= -DKRB5_KEYTABC_PATH=\"$(DESTDIR)/sbin/krb5_keytabc\"

all:
	cd scripts	&& $(MAKE) PERL='$(PERL)'
	cd suid_helper	&& $(MAKE) CFLAGS='$(CFLAGS)'

install:
	umask 022 && mkdir -p $(SBIN)
	umask 022 && mkdir -p $(MAN5)
	umask 022 && mkdir -p $(MAN8)
	umask 022 && mkdir -p $(EXAMPL)
	install -c -m 4755 -o root	suid_helper/krb5_keytab	$(SBIN)
	install -c -m 755		scripts/krb5_keytabc	$(SBIN)
	install -c -m 644		man/krb5_keytab.conf.5	$(MAN5)
	install -c -m 644		man/krb5_keytab.8	$(MAN8)
	install -c -m 644		etc/krb5_keytab.conf			$(EXAMPL)

clean:
	cd scripts	&& $(MAKE) clean
	cd suid_helper	&& $(MAKE) clean
