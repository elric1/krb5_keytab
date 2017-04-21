#!/usr/pkg/bin/perl
#

use Getopt::Std;
use Sys::Syslog;

use Data::Dumper;

use Krb5Admin::Krb5Host::Local;

use strict;
use warnings;

our $KRB5_KEYTAB_CONFIG = '@@KRB5_KEYTAB_CONF@@';

sub pretty_print_libs {
	my ($fh, @libs) = @_;
 
	for my $i (@libs) {
		printf $fh ("\t%- 30.30s %s\n", $i->[0],
		    $i->[1] ? '[deprecated]' : '');
	}
}

sub format_install {

	for my $line (@_) {
		print "$line\n" if defined($line);
	}
}

#
# format_list will format the return of the list command which is
# expected to be a hash containing two values, ktname and keys.
# keys is a list of hashes with entries kvno, princ, and enctype.

sub format_list {
	my ($output) = @_;

	my $ktname = $output->{ktname};
	my $keys   = $output->{keys};

	print "Keytab name: $ktname\n";
	print "KVNO Principal\n";
	print "---- --------------------------------------------------" .
	    "------------------------\n";

	# XXXrcd: we're changing the enctype here to an alias...
	# XXXrcd: ...and we shouldn't print in an object, should we?

	for my $key (@$keys) {
		printf("%4d %s (%s)\n", $key->{kvno}, $key->{princ},
		    $key->{enctype});
	}
}

#
# format_query will format the output of query which is a hashref
# of principals (string) to a list of supported libs which are
# represented as an array ref of [string, boolean] where the string
# is the library name and the boolean undicates if the library is
# considered to be deprecated.

sub format_query {
	my ($output) = @_;

	my @princs = keys %$output;

	print "Keytab contains " . scalar(@princs) . " principal";
	print "s" if scalar(@princs) != 1;
	print "\n";

	for my $i (@princs) {
		print "\n\nPrincipal $i can work with the following\n";
		print "Kerberos libraries:\n\n";

		printf 
		pretty_print_libs(\*STDOUT, @{$output->{$i}});
	}
}

sub format_generate {
	my ($errs, $output) = @_;

	for my $line (@$errs) {
		print STDERR "$line\n";
	}

	for my $line (@$output) {
		print "$line\n";
	}
}

#
# These variables are expected to be set in the configuration file:

our $verbose = 0;
our %user2service = ();
our @allowed_enctypes = ();
our @admin_users = ();
our %krb5_libs = ();
our %krb5_lib_quirks = ();
our $default_krb5_lib = ();
our %user_libs = ();
our $use_fetch = 0;
our $ext_sync_func;

#
# Done: config file.

#
# Cmd line syntax:

sub usage {
	my ($kt) = @_;

	print STDERR <<EOM;
usage: krb5_keytab [-fv] [-p <user>] [-L libver] [<sprinc> ...]
       krb5_keytab -c [-fv] [-p <user>] [<sprinc> ...]
       krb5_keytab -g [-fv] [-p <user>] [<sprinc> ...]
       krb5_keytab -l [-fv] [-p <user>]
       krb5_keytab -q [-fv] [-p <user>] [<sprinc> ...]
       krb5_keytab -t [-fv] [-p <user>] [-L libver] [<sprinc> ...]

For full usage please refer to the man page:

	\$ man krb5_keytab

The ``-L libver'' option specifies which version of the Kerberos libraries
your server uses.  Please note that if you choose the wrong library,
your application will fail to function in unusual ways.  It is your
responsibility to select the appropriate Kerberos library versions that
correspond to your application.

The default library version is $default_krb5_lib.

The following libraries are supported for self-service:

EOM

	my @ss = grep { ! $kt->lib_requires_admin($_) } (keys %krb5_libs);
	pretty_print_libs(\*STDERR,
	    map { [ $_, 0 ] } $kt->sort_libs(@ss));

	print STDERR <<EOM;

The following libraries are only supported by administrators:

EOM

	my @manual = grep { $kt->lib_requires_admin($_) } (keys %krb5_libs);
	pretty_print_libs(\*STDERR,
	    map { [ $_, 1 ] } $kt->sort_libs(@manual));

	print STDERR "\nFor more information, please refer to the man page.\n";
	exit(1);
}

do $KRB5_KEYTAB_CONFIG if -f $KRB5_KEYTAB_CONFIG;
print $@ if $@;

my $kt = Krb5Admin::Krb5Host::Local->new(
	interactive		=> 1,
	user2service		=> \%user2service,
	allowed_enctypes	=> \@allowed_enctypes,
	admin_users		=> \@admin_users,
	krb5_libs		=> \%krb5_libs,
	krb5_lib_quirks		=> \%krb5_lib_quirks,
	default_krb5_lib	=>  $default_krb5_lib,
	user_libs		=> \%user_libs,
	use_fetch		=>  $use_fetch,
	ext_sync_func		=>  $ext_sync_func,
);

# The <invoking_user> parameter specifies the ``authenticated'' user when we
# are invoked via a suid script.  It's a little odd to _require_ a flagged
# argument but we do this to preserve the interface with the suid wrapper.
# In the wrapper, the -u argument is implied to be the ruid.
#

our %opts;
my $force;
my $action;
my $kmdb;
my $got_tickets = 0;
my $krb5_lib;
my $xrealm;

# XXXrcd: getopt error?
getopts('AFL:R:UW:X:Zcfglqp:tu:vw?', \%opts) or usage($kt);

usage($kt) if defined($opts{'?'});

my $invoking_user = $opts{u};
if (!defined($invoking_user)) {
	print STDERR "Improperly invoked, must use wrapper.\n";
	exit(1);
}

my $user = $opts{p} // $invoking_user;

#if (defined($opts{A}) || defined($opts{Z})) {
#	if ($invoking_user ne 'root' && !$admin_users{$invoking_user}) {
#		die "-A and -Z require administrative access.";
#	}
#}

$krb5_lib = $opts{L}		if defined($opts{L});
$xrealm   = $opts{X}		if defined($opts{X});
$action   = 'install_keytab';
$action   = 'change_keytab'	if defined($opts{c});
$action   = 'list_keytab'	if defined($opts{l});
$action   = 'query_keytab'	if defined($opts{q});
$action   = 'test_keytab'	if defined($opts{t});
$action   = 'generate_keytab'	if defined($opts{g});

$kt->set_opt('invoking_user', $opts{u});
$kt->set_opt('verbose', defined($opts{v}) ? 1 : 0);
$kt->set_opt('userqual', defined($opts{U}) ? 1 : 0);
$kt->set_opt('local', defined($opts{Z}) ? 1 : 0);
$kt->set_opt('kadmin', defined($opts{A}) ? 1 : 0);
$kt->set_opt('xrealm', $opts{X});
$kt->set_opt('ktroot', $opts{R});

$kt->set_opt('force', 0);
$kt->set_opt('force', 1)	if defined($opts{f});
$kt->set_opt('force', 2)	if defined($opts{F});

if (defined($opts{w}) && defined($opts{W})) {
	die "-W and -w are mutally exclusive.\n";
}

if (defined($opts{w}) && !defined($opts{X})) {
	die "specifying -w requires -X.\n";
}

if ((defined($opts{W}) || defined($opts{X})) && defined($opts{A})) {
	die "-A may not be specified with either -W or -X.\n";
}

#
# First we setup syslog.

openlog('krb5_keytab', 'pid', 'auth');

my $errs;
my @output;
eval {
	my $f = $kt->can($action);

	@output = &$f($kt, $user, $krb5_lib, @ARGV);

	format_install(@output)		if $action eq 'install_keytab';
	format_list(@output)		if $action eq 'list_keytab';
	format_query(@output)		if $action eq 'query_keytab';
	format_generate(@output)	if $action eq 'generate_keytab';
};

$errs =  $@	if $@;
$errs = [$@]	if defined($errs) && ref($errs) ne 'ARRAY';

my $num_errs = 0;
for my $err (@$errs) {
	print STDERR "$err\n";
	$num_errs++;
}

if ($num_errs == 1) {
	print STDERR "1 error was encountered.\n";
	exit(1);
}
if ($num_errs > 0) {
	print STDERR "$num_errs errors were encountered.\n";
	exit(1);
}

exit(0);
