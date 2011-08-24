#
#

PREFIX		?= /usr
PERL		?= /usr/bin/perl
KINIT		?= /usr/bin/kinit
KLIST		?= /usr/bin/klist
KDESTROY	?= /usr/bin/kdestroy
KRB5_KEYTAB_CONF?= /etc/krb5/krb5_keytab.conf

all: krb5_keytabc

clean:
	rm -f krb5_keytabc

krb5_keytabc: krb5_keytabc.pl
	< krb5_keytabc.pl > krb5_keytabc				\
	    sed -e '1s,.*,#!$(PERL),'					\
		-e 's,@@KRB5_KEYTAB_CONF@@,$(KRB5_KEYTAB_CONF),'	\
		-e 's,@@KINIT@@,$(KINIT),g'				\
		-e 's,@@KLIST@@,$(KLIST),g'				\
		-e 's,@@KDESTROY@@,$(KDESTROY),g'
