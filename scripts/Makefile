#
#

all: krb5_keytabc

clean:
	rm -f krb5_keytabc

krb5_keytabc: krb5_keytabc.pl
	< krb5_keytabc.pl > krb5_keytabc sed -e '1s,.*,#!$(PERL),'
