#!/usr/pkg/bin/perl
#

use Getopt::Std;
use IO::File;
use IPC::Open3;
use File::Path;
use File::Temp qw/ :mktemp /;
use Fcntl ':flock';
use POSIX qw(strftime);
use Sys::Hostname;
use Sys::Syslog;
use Time::HiRes qw(gettimeofday);

use Krb5_Admin::Client;
use Krb5_Admin::Utils qw/host_list/;
use Krb5_Admin::C::krb5_keytab;

# XXXrcd: just for testing:
use Data::Dumper;

use strict;
use warnings;

#
# Constants:

our $KRB5_KEYTAB_CONFIG = '/ms/dist/kerberos/etc/krb5_keytab.conf';
our $KLIST    = '/ms/dist/kerberos/PROJ/mitkrb5/1.4-lib-prod/bin/klist';
our $KINIT    = '/ms/dist/kerberos/PROJ/mitkrb5/1.4-lib-prod/bin/kinit';
our $KDESTROY = '/ms/dist/kerberos/PROJ/mitkrb5/1.4-lib-prod/bin/kdestroy';

#
# These variables are expected to be set in the configuration file:

our %proid2service = ();
our @allowed_enctypes = ();
our @admin_users = ();
our %krb5_libs = ();
our %krb5_lib_quirks = ();
our $default_krb5_lib = ();
our %proid_libs = ();

our %enctypes = (
	0x12	=> 'aes256-cts',
	0x11	=> 'aes128-cts',
	0x17	=> 'rc4-hmac',
	0x10	=> 'des3-cbc-sha1',
	0x01	=> 'des-cbc-crc',
);
our %revenctypes;
for my $i (keys %enctypes) {
	$revenctypes{$enctypes{$i}} = $i;
}

#
# Done: config file.

our @instances;
our $force = 0;
our $ret;

our $verbose = 0;
sub vprint {

	if ($verbose > 0) {
		my ($s, $us) = gettimeofday();
		my $t = sprintf("%s.%06s -[%5d]- ",
		    strftime("%Y-%m-%d %T", localtime($s)), $us, $$);
		print STDERR $t, @_;
	}
}

sub format_err {
	my ($at) = @_;

	return $at->[0] . ": " . $at->[1]	if ref($at) eq 'ARRAY';
	return $at->{errstr}			if ref($at) eq 'HASH';
	return $at;
}

sub get_proid_uid {
	my @pwd = getpwnam($_[0]);

	die "can't determine uid for $_[0]" if @pwd != 9;

	($pwd[2], $pwd[3]);
}

sub in_set {
	my ($member, $set) = @_;

	for my $i (@$set) {
		return 1 if $i eq $member;
	}
	return 0;
}

sub is_subset {
	my ($subset, $set) = @_;
	my %tmp;

	for my $i (@$set) { $tmp{$i} = 1 }
	for my $i (@$subset) {
		return 0 if !$tmp{$i};
	}
	return 1;
}

sub enctypes_require_admin {
	! scalar(grep { $_ =~ /^aes[12]/ } @_) ||
	  scalar(grep { $_ eq 'des-cbc-crc' } @_);
}

sub lib_requires_admin {
	enctypes_require_admin(@{$krb5_libs{$_[0]}});
}

sub lib_better {
	my ($a, $b) = @_;
	my @a = grep { $_ ne 'des-cbc-crc' } @{$krb5_libs{$a}};
	my @b = grep { $_ ne 'des-cbc-crc' } @{$krb5_libs{$b}};

	return  1	if is_subset(\@a, \@b);
	return -1	if is_subset(\@b, \@a);
	return scalar(@b) <=> scalar(@a);
}

sub sort_libs { sort { lib_better($a, $b) } @_; }

#
# Hereafter we find the library quirk logic.  We have two functions here,
# the first will determine if a set of keys representing a keytab satisfies
# the current library's quirks.  The other one will fix the list.  The idea
# is that if lib_quirks() fails, then you have to create a new keytab by
# using the output of fix_quirks().  We implement two quirks currently,
# the first deals with Java Dain Brammage, i.e. the keys must be in order
# in the keytab.  The second deals with libraries that throw errors if they
# come across enctypes they don't grok.  This list may grow with time...

sub keys_sorted {
	my ($order, @keys) = @_;
	my %princs;
	my $kvno;

	if ($order ne 'ascending' && $order ne 'descending') {
		die "keys_sorted called inappropriately...";
	}

	for my $i (@keys) {
		$kvno = $princs{$i->{princ}};
		$princs{$i->{princ}} = $i->{kvno};

		next		if !defined($kvno);
		return 0	if $order eq 'ascending'  && $kvno > $i->{kvno};
		return 0	if $order eq 'descending' && $kvno < $i->{kvno};
	}

	return 1;
}

sub is_quirky {
	my ($lib, @keys) = @_;

	return 0 if !defined($lib) || !exists($krb5_lib_quirks{$lib});

	if (in_set('ascending', $krb5_lib_quirks{$lib})) {
		return 1 if (!keys_sorted('ascending', @keys));
	}

	if (in_set('descending', $krb5_lib_quirks{$lib})) {
		return 1 if (!keys_sorted('descending', @keys));
	}

	if (in_set('nounsupp', $krb5_lib_quirks{$lib})) {
		for my $i (@keys) {
			if (!in_set($i->{enctype},
			    ['des-cbc-crc', @{$krb5_libs{$lib}}])) {
				return 1;
			}
		}
	}

	return 0;
}

sub fix_quirks {
	my ($lib, @keys) = @_;

	return @keys if !defined($lib);
	return @keys if !exists($krb5_lib_quirks{$lib});

	vprint "Fixing keytab quirks " . join(', ', @{$krb5_lib_quirks{$lib}}) .
	    " for library: $lib\n";
	if (in_set('nounsupp', $krb5_lib_quirks{$lib})) {

		my @libenc = ('des-cbc-crc', @{$krb5_libs{$lib}});
		@libenc = map { $revenctypes{$_} } @libenc;

		@keys = grep { in_set($_->{enctype}, \@libenc) } @keys;

	}

	if (in_set('ascending', $krb5_lib_quirks{$lib})) {
		@keys = sort {$a->{kvno} <=> $b->{kvno}} @keys;
	}

	if (in_set('descending', $krb5_lib_quirks{$lib})) {
		@keys = sort {$b->{kvno} <=> $a->{kvno}} @keys;
	}

	@keys;
}

sub latest_key_etypes {
	my ($princ, @keys) = @_;
	my $maxkvno = -1;
	my @ret;

	for my $i (@keys) {
		next		if ($i->{princ} ne $princ);
		next		if ($i->{kvno} < $maxkvno);
		@ret = ()	if ($i->{kvno} > $maxkvno);
		push(@ret, $i->{enctype});
		$maxkvno = $i->{kvno};
	}

	@ret;
}

sub supports_libs {
	my ($princ, @keys) = @_;
	my @ret;

	my $enclist = [ latest_key_etypes($princ, @keys) ];

	@ret = grep { is_subset($enclist,
	    ['des-cbc-crc', @{$krb5_libs{$_}}]) } (keys %krb5_libs);

	#
	# Now we have to map this against a quirk table that we
	# define.  This is rather unfortunate, but we must deal
	# with a level of dain brammage in Java and old MIT krb5.

	@ret = grep { !is_quirky($_, @keys) } @ret;

	#
	# And now we sort them into an order of preference for display.
	# This is just to encourage correct behaviour.

	sort_libs(@ret);
}

sub working_lib {
	my ($princ, @keys) = @_;

	my $enclist = [ latest_key_etypes($princ, @keys) ];

	my ($ret) = grep { is_subset($krb5_libs{$_}, $enclist) }
	    supports_libs($enclist);
	$ret;
}

#
# parse_princ returns a list of the form:
#
#       (REALM, component[, component, ...])
#
# from a Kerberos principal.
#
# XXXrcd: currently lame insofar as it only parses up to 2 components...
# XXXrcd: also lame because we default to is1.morgan: should get default
#         realm...
# XXXrcd: also lame because it is cut and pasted from krb5_admin.

sub parse_princ {

        # XXXrcd: die if called from scalar context?

        if ($_[0] =~ m,[^-A-Za-z0-9_/@.],) {
                die [503, "Malformed principal name"];
        }

        $_[0] =~ m,^([^/@]+)(?:/([^/@]+))?(?:@([^/@]+))?$,;

        die [503, "Malformed principal in parse_princ"] if !defined($1);

        my @ret = (defined($3)?$3:'is1.morgan', $1);
        push(@ret, $2) if (defined($2));
        @ret;
}

# XXXrcd: maybe we should perform a little validation later.
# XXXrcd: also lame because it is code duplication.
sub unparse_princ {

	$_[0]->[1] . '/' . $_[0]->[2] . '@' . $_[0]->[0];
}

#
# Munge the output of Krb5_Admin::C::read_kt into something
# that is a little easier for me to deal with:

sub get_keys {
	my ($kt) = @_;
	my $ctx = Krb5_Admin::C::krb5_init_context();

	$kt = "FILE:/etc/krb5.keytab" if !defined($kt) || $kt eq '';
	my @ktkeys = Krb5_Admin::C::read_kt($ctx, $kt);

	for my $i (@ktkeys) {
		$i->{enctype} = $enctypes{$i->{enctype}};
	}
	@ktkeys;
}

sub get_princs {
	my %ret;

	for my $i (@_) {
		$ret{$i->{princ}} = 1;
	}
	keys %ret;
}

#
# calculate the instances that we may need to fetch.

sub get_instances {
	my @tmp;
	my %ret;

	@tmp = map { [ parse_princ($_->{princ}) ] } (get_keys(''));
	for my $i (grep { $_->[1] eq 'host' } @tmp) {
		$ret{$i->[2]} = 1;
	}
	keys %ret;
}

#
# expand_princs takes an array ref representing a single princ and
# returns a list of said array refs.  The expansion is:
#
#	1.  populate the realm as is1.morgan (hardcoded, bad.)
#
#	2.  if the instance is not specified then generalise from
#	    the global var @instances which is derived from
#	    /etc/krb5.keytab.  After all, this _is_ the maximal
#	    set that we could ever hope to fetch.

sub expand_princs {
	my ($pr) = @_;

	$pr->[0] = "is1.morgan"	if $pr->[0] eq '';

	if ($pr->[2] eq '') {
		return map { [ $pr->[0], $pr->[1], $_ ] } @instances;
	} else {
		return ($pr);
	}
}


#
# check_acls takes a single proid and a list of principals specified
# as listrefs: [ REALM, name, instance ] and will exit if the requested
# operation is disallowed.
#
# This only checks if the proid's keytab is allowed to contain the service
# principals requested and is used to allow, e.g. imapsvr to install keys
# for imap/hostname@REALM into /var/spool/keytabs/imapsvr if you are running
# your imap servers as the imapsvr user in your environment.
#
# Okay.  Now, we have a list of array refs representing the requested
# principals.  We need to do a little sanity checking on the data.  What
# we're doing here is a tad odd from first sight, but the configuration
# file contains a variable %proid2service which is a hash which keys on
# the proid.  The value is an array ref of services which the proid is
# allowed to request in its keytabs.  We extract this array ref and turn
# it into a hash so that it can be used as a constant time lookup in the
# grep.  We also add $proid to the hash for good measure as we implicitly
# allow the proid to request keys for the service of the same name...

sub check_acls {
	my ($proid, @services) = @_;
	my $err;

	return if $proid eq 'root';

	our %acl_svcs;
	$proid2service{$proid} = [] if !defined($proid2service{$proid});
	%acl_svcs = map { $_ => 1 } @{$proid2service{$proid}};
	$acl_svcs{$proid} = 1;

	for my $i (grep { !defined($acl_svcs{$_->[1]}) } @services) {
		print STDERR "Permission denied: $proid can't create " .
		    unparse_princ($i) . "\n";
		$err = 1;
	}

	exit(1) if defined($err);
}

sub obtain_lock {
	my ($lockdir, $lockfile) = @_;

	#
	# Here we pessimistically create the lock directory.  Because this is
	# in /var/run, we assume that only root can create it---but just to be
	# sure we hammer the perms and ownership in the right way.  We use
	# mkpath to ensure that we create /var/run on SunOS 5.7 which
	# surprisingly doesn't come with it...

	mkpath($lockdir, 0, 0700);
	chmod(0700, $lockdir);
	chown(0, 0, $lockdir);

 	my @s = stat($lockdir);
 	die("lock directory invalid")
 	    if (!@s || $s[2] != 040700 || $s[4] || $s[5]);

	vprint "obtaining lock: $lockfile\n";

	my $lock_fh = new IO::File($lockfile, O_CREAT|O_WRONLY)
	    or die "Could not open lockfile $lockfile: $!";
	flock($lock_fh, LOCK_EX) or die "Could not obtain lock: $!";

	vprint "lock obtained\n";
}

#
# get_kt() determines the location of the keytab based on the proid on
# which we are operating.

sub get_kt {
	my ($proid) = @_;

	return "WRFILE:/var/spool/keytabs/$proid" if $proid ne 'root';
	return 'WRFILE:/etc/krb5.keytab';
}

sub pretty_print_libs {
	my $fh = shift;

	for my $i (@_) {
		printf $fh ("\t%- 30.30s %s\n", $i,
		    lib_requires_admin($i) ? '[deprecated]' : '');
	}
}

sub query_keytab {
	my ($proid) = @_;
	my @keys = get_keys(get_kt($proid));
	my @princs = get_princs(@keys);

	print "Keytab contains " . scalar(@princs) . " principals\n";

	for my $i (@princs) {
		print "\n\nPrincipal $i can work with the following\n";
		print "Kerberos libraries:\n\n";

		pretty_print_libs(\*STDOUT, supports_libs($i, @keys));
	}
}

sub test_keytab {
	my ($proid, $lib, @inprincs) = @_;
	my @keys = get_keys(get_kt($proid));
	my @princs = get_princs(@keys);
	my $err = 0;

	$lib = $default_krb5_lib if !defined($lib);

	for my $i (map { unparse_princ($_) } @inprincs) {
		vprint "Testing $i\n";
		if (!in_set($i, [@princs])) {
			print STDERR "$i does not exist in the keytab.\n";
			$err++;
			next;
		}
		if (!in_set($lib, [supports_libs($i, @keys)])) {
			print STDERR "$i will not work with $lib.\n";
			$err++;
		}
	}
	return $err;
}

sub generate_keytab {
	my ($proid, @inprincs) = @_;
	my @keys = get_keys(get_kt($proid));
	my @princs = get_princs(@keys);
	my @errs;
	my $err = 0;

	for my $i (@inprincs) {
		if (!in_set($i, [@princs])) {
			push(@errs, "$i does not exist in the keytab.\n");
			next;
		}
		my $working_lib = working_lib($i, @keys);

		if (!defined($working_lib) || (exists($proid_libs{$proid}) &&
		    !in_set($working_lib, $proid_libs{$proid}))) {
			$working_lib = $proid_libs{$proid}->[0];
		}

		if (!defined($working_lib)) {
			push(@errs, "Can't determine library for $i.\n");
			next;
		}

		print "krb5_keytab -p $proid -L " . $working_lib . " $i\n";
	}

	for my $i (@errs) {
		print $i;
		$err++;
	}
	return $err;
}

#
# Here, what we do is a kinit(1) for the key and check the return code.
# If the kinit(1) is successful, then it's quite likely that we do not
# need to contact the KDC and so we don't.  This is is heuristic that we
# expect to work almost all the time.  And if it fails for some reason,
# then we simply contact the KDC which is not a problem.

sub need_new_key {
	my ($kt, $key) = @_;

	qx{$KINIT -cMEMORY:foo "-kt$kt" "$key" > /dev/null 2>&1};
	return 1 if $? != 0;
	return 0;
}

sub mk_keys	{
	my $ctx = Krb5_Admin::C::krb5_init_context();

	map {Krb5_Admin::C::krb5_make_a_key($ctx, $_)} @_;
}

sub ktuniq {
	my @keys = @_;
	my %princs;
	my @ret;

	for my $i (@keys) {
		push(@{$princs{$i->{princ}}->{$i->{kvno}}}, $i);
	}

	for my $i (keys %princs) {
		for my $j (keys %{$princs{$i}}) {
			push(@ret, @{$princs{$i}->{$j}});
		}
	}

	@ret;
}

sub write_keys_internal {
	my ($ctx, $lib, $kt, @keys) = @_;

	vprint "Starting to write keys in write_keys_internal...\n";
	for my $i (fix_quirks($lib, @keys)) {
		next if $i->{enctype} == 0;

		vprint "Writing (" . $i->{princ} . ", " .
		    $i->{kvno} . ", " . $i->{enctype} . ")\n";

		Krb5_Admin::C::write_kt($ctx, $kt, $i);
	}
	vprint "Finished writing keys in write_keys_internal...\n";
}

sub write_keys_kt {
	my ($proid, $lib, $princ, $kvno, @keys) = @_;
	my $oldkt;
	my $kt = get_kt($proid);
	my $ctx = Krb5_Admin::C::krb5_init_context();

	for my $i (@keys) {
		$i->{princ} = $princ	if defined($princ);
		$i->{kvno}  = $kvno	if defined($kvno);
	}

	write_keys_internal($ctx, $lib, $kt, @keys);

	my @ktkeys;
	eval { @ktkeys = Krb5_Admin::C::read_kt($ctx, $kt); };

	return if $force < 2 && !is_quirky($lib, @ktkeys);

	vprint "Recreating keytab file fixing quirks...\n";

	$oldkt = $kt;
	$oldkt =~ s/WRFILE://;
	unlink("$oldkt.tmp");
	$kt = "WRFILE:$oldkt.tmp";
	@keys = ktuniq(@ktkeys, @keys);

	write_keys_internal($ctx, $lib, $kt, @keys);

	$kt =~ s/^WRFILE://;
	chmod(0400, $kt)			or die "chmod: $!";
	chown(get_proid_uid($proid), $kt)	or die "chown: $!";
	rename($kt, $oldkt)			or die "rename: $!";

	vprint "New keytab file rename(2)ed into position, quirk-free\n";
}

#
# XXXrcd: install_keys assumes that all keys to be installed can
#         be fetched by a single Kerberos principal, i.e. that they
#         have the same host instance and realm.  For a different
#         host instance/realm, you must use a different connexion.

sub install_keys {
	my ($kmdb, $action, $lib, $instance, $proid, @names) = @_;
	my $kt = get_kt($proid);
	my @ret;
	my $etypes;

	$etypes = $krb5_libs{$lib} if defined($lib);

	if ($action ne 'change' && $force < 1) {
		@names = grep { need_new_key($kt, $_) } @names;
	}

	for my $princ (@names) {
		vprint "installing: $princ\n";
		if (!defined($kmdb)) {
			$kmdb = Krb5_Admin::Client->new("host/$instance",
			    { port => 'krb5_keytab' });
		}
		# For change, we force ourselves to chat with the master
		# by executing a failing change() method...
		$kmdb->master() if $action eq 'change';

		eval { @ret = $kmdb->fetch($princ) };
		if ($@) {
			die $@ if $action ne 'default';
			vprint "fetch error: " . format_err($@) . "\n";
			vprint "creating: $princ\n";
			eval {
				$kmdb->create($princ);
				if (defined($etypes)) {
					$kmdb->change($princ, -1,
					    [mk_keys(@$etypes)]);
				}
			};
			if ($@) {
				vprint "creation error: ".format_err($@)."\n";
			}
			@ret = $kmdb->fetch($princ);
		}

		write_keys_kt($proid, $lib, $princ, undef, @ret);

		next if $action ne 'change';

		# Find the max kvno:
		my $kvno = -1;
		for my $i (@ret) {
			$kvno = $i->{kvno} if $i->{kvno} > $kvno;
		}
		die "Could not determine max kvno" if $kvno == -1;

		if (!defined($etypes)) {
			my %enctypes;

			for my $i (grep {$_->{kvno} == $kvno} @ret) {
				$enctypes{$i->{enctype}}=1;
			}
			$etypes = [ keys %enctypes ];
		}
		$kvno++;
		my @keys = mk_keys(@$etypes);
		write_keys_kt($proid, $lib, $princ, $kvno, @keys);
		$kmdb->change($princ, $kvno, \@keys);
	}
}

#
# install_all_keys just takes:
#
#	1.  the keytab location,
#
#	2.  the proid, and
#
#	3.  a simple list of principals which are represented by
#	    listrefs [ REALM, service, instance ].  It breaks up
#	    the requests into groups with like instances and calls
#	    install_keys().
#
# It works by building a hash of instance => [ princs ] and iterating
# over the keys of that map calling install_keys.

sub install_all_keys {
	my ($proid, $kmdb, $action, $lib, @princs) = @_;
	my %instmap;
	my $kt = get_kt($proid);
	my $errs = 0;

	vprint "checking acls...\n";
	check_acls($proid, @princs);		# this will exit on failure.

	for my $i (@princs) {
		push(@{$instmap{$i->[2]}}, unparse_princ($i));
	}

	for my $i (keys %instmap) {
		vprint "installing keys for instance $i...\n";
		eval {
			install_keys($kmdb, $action, $lib, $i, $proid,
			    @{$instmap{$i}});
		};
		if ($@) {
			print STDERR (format_err($@) . "\n");
			print STDERR "Failed to install keys $i\n";
			syslog('err', "Failed to install (%s) keys for %s " .
			    "instance %s, %s", $action, $proid, $i,
			    format_err($@));
			$errs++;
		} else {
			syslog('info', "Installed (%s) keys for %s " .
			    "instance %s", $action, $proid, $i);
		}
	}

	$kt =~ s/^WRFILE://;
	chmod(0400, $kt)                            or die "chmod: $!";
	chown(get_proid_uid($proid), $kt)           or die "chown: $!";

	vprint "Successfully updated keytab file\n" if $errs == 0;
	return $errs;
}

#
# Cmd line syntax:

sub usage {

	print STDERR <<EOM;
usage: krb5_keytab [-fv] [-p <proid>] [-L libver] [<sprinc> ...]
       krb5_keytab -c [-fv] [-p <proid>] [<sprinc> ...]
       krb5_keytab -g [-fv] [-p <proid>] [<sprinc> ...]
       krb5_keytab -l [-fv] [-p <proid>]
       krb5_keytab -q [-fv] [-p <proid>] [<sprinc> ...]
       krb5_keytab -t [-fv] [-p <proid>] [-L libver] [<sprinc> ...]

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

	my @self_service = grep { ! lib_requires_admin($_) } (keys %krb5_libs);
	pretty_print_libs(\*STDERR, sort_libs(@self_service));

	print STDERR <<EOM;

The following libraries are only supported by filing a Falcon ticket to
the RMC for provisioning:

EOM

	my @manual = grep { lib_requires_admin($_) } (keys %krb5_libs);
	pretty_print_libs(\*STDERR, sort_libs(@manual));

	print STDERR "\nFor more information, please refer to the man page.\n";
	exit(1);
}

# The <invoking_user> parameter specifies the ``authenticated'' user when we
# are invoked via a suid script.  It's a little odd to _require_ a flagged
# argument but we do this to preserve the interface with the suid wrapper.
# In the wrapper, the -u argument is implied to be the ruid.
#

#
# Here are the main guts of the program:

do $KRB5_KEYTAB_CONFIG if -f $KRB5_KEYTAB_CONFIG;
print $@ if $@;

our %opts;
my $errs = 0;
my $action;
my $kmdb;
my %admin_users;
my $krb5_lib;

%admin_users = map { $_ => 1 } @admin_users;

# XXXrcd: getopt error?
getopts('AFL:Rcfglqp:rtu:v?', \%opts) or usage();

usage() if defined($opts{'?'});

my $invoking_user = $opts{u};
if (!defined($invoking_user)) {
	print STDERR "Improperly invoked, must use wrapper.\n";
	exit(1);
}

my $proid = $opts{p};
if (!defined($proid)) {
	$proid = $invoking_user;
}
if (!defined(getpwnam($proid))) {
	print STDERR "User ID $proid does not exist.\n";
	exit(1);
}

if ($invoking_user ne $proid && $invoking_user ne 'root' &&
    !$admin_users{$invoking_user}) {
	print STDERR "Access Denied for operation, $invoking_user does not\n";
	print STDERR "have krb5_keytab administrative privileges.\n";
	exit(1);
}

$krb5_lib = $opts{L}			if defined($opts{L});
if (defined($krb5_lib)) {
	if (!defined($krb5_libs{$krb5_lib})) {
		print STDERR "Library \"$krb5_lib\" is not defined.\n\n";
		usage();
	}

	my $enctypes = $krb5_libs{$krb5_lib};
	if (!is_subset($enctypes, [@allowed_enctypes])) {
		print STDERR "Invalid encryption type(s) [" .
		    join(',', grep {!in_set($_, [@allowed_enctypes])}
		    @$enctypes) .  "] specified.\n";
		usage();
	}
}

$verbose = 1		if defined($opts{'v'});
$force   = 1		if defined($opts{'f'});
$force   = 2		if defined($opts{'F'});
$action  = 'default';
$action  = 'change'	if defined($opts{'c'});
$action  = 'list'	if defined($opts{'l'});
$action  = 'query'	if defined($opts{'q'});
$action  = 'test'	if defined($opts{'t'});
$action  = 'generate'	if defined($opts{'g'});

@ARGV = ($proid) if (scalar(@ARGV) == 0);

my ($fh, $ccname) = mkstemp("/tmp/krb5_keytab_ccXXXXXX");
undef($fh);
$ENV{KRB5CCNAME} = "FILE:$ccname";

#
# First we setup syslog.

openlog('krb5_keytab', 'pid', 'auth');

#
# XXXrcd: UGLY!
#

#
# We first special case the -A ``administrative'' function.  This sucks,
# but we'll fix the code later when caffeine is a new experience for the
# day.  After this much, aceroa is encouraging that we complete the task
# before The Wife says [more] nasty things about Me.

my @princs;
if (defined($opts{A})) {
	if ($invoking_user ne 'root' && !$admin_users{$invoking_user}) {
		die "-A requires administrative access.";
	}

	print "Please enter your Kerberos administrative principal\n";
	print "This is generally your username followed by ``/admin'',\n";
	print "I.e.: user/admin\n\n";

	for (my $i=0; $i < 10; $i++) {
		print "Admin principal: ";
		my $admin = <STDIN>;

		chomp($admin);

		if ($admin !~ m,[a-z0-9A-Z]+/admin,) {
			print "Invalid Kerberos admin principal.\n";
			next;
		}

		system($KINIT, '-l', '10m', $admin) and next;
		$kmdb = Krb5_Admin::Client->new();
		last;
	}

	@princs = map { ['is1.morgan', 'host', $_ ] } (host_list(hostname()));
	$proid = 'root';
} else {

	# UGLY!

	@instances = get_instances();
	@princs = map { expand_princs([ parse_princ($_) ]) } @ARGV;
}

#
# XXXrcd: this all needs to be refactored.

if ($action eq 'list') {
	if (!$admin_users{$invoking_user}) {
		syslog('err', "%s attempted to list %s's keytab",
		    $invoking_user, $proid);
		die "list is an administrative function only.";
	}
	syslog('info', "%s listed %s's keytab", $invoking_user, $proid);
	system $KLIST ($KLIST, '-ekt', get_kt($proid));
	system $KDESTROY;
	exit(0);
}

if ($action eq 'query') {
	syslog('info', "%s queried %s's keytab", $invoking_user, $proid);
	query_keytab($proid);
	system $KDESTROY;
	exit(0);
}

if ($action eq 'generate') {
	$errs += generate_keytab($proid, map {unparse_princ($_)} @princs);
	system $KDESTROY;

	if ($errs == 1) {
		syslog('err', "%s generated from %s's keytab resulting in 1" .
		    " error", $invoking_user, $proid);
		print STDERR "1 error was encountered.\n";
		exit(1);
	}
	if ($errs > 0) {
		syslog('err', "%s generated from %s's keytab resulting in %d" .
		    " errors", $invoking_user, $proid, $errs);
		print STDERR "$errs errors were encountered.\n";
		exit(1);
	}
	syslog('info', "%s generated from %s's keytab successfully",
	    $invoking_user, $proid);
	vprint "No errors were encountered.\n";
	exit(0);
}

#
# This test occurs after all the non-change options:

my $real_krb5_lib = $default_krb5_lib;
$real_krb5_lib = $krb5_lib if defined($krb5_lib);
if (defined($real_krb5_lib) && exists($proid_libs{$proid}) &&
    !in_set($real_krb5_lib, $proid_libs{$proid})) {
	print STDERR "$proid does not support $real_krb5_lib.\n";
	exit(1);
}

if ($action eq 'test') {
	$errs += test_keytab($proid, $krb5_lib, @princs);
	system $KDESTROY;

	if ($errs == 1) {
		syslog('err', "%s tested %s's keytab against %s resulting in ".
		    "1 error", $invoking_user, $proid, $krb5_lib);
		print STDERR "1 error was encountered.\n";
		exit(1);
	}
	if ($errs > 0) {
		syslog('err', "%s tested %s's keytab against %s resulting in ".
		    "%d errors", $invoking_user, $proid, $krb5_lib, $errs);
		print STDERR "$errs errors were encountered.\n";
		exit(1);
	}
	syslog('info', "%s tested %s's keytab against %s successfully",
	    $invoking_user, $proid, $krb5_lib);
	vprint "No errors were encountered.\n";
	exit(0);
}

if (defined($krb5_lib) && lib_requires_admin($krb5_lib) &&
    !$admin_users{$invoking_user}) {
	print STDERR "Setting Kerberos library to $krb5_lib" .
	    " requires krb5_keytab\nadministrative rights.\n";
	usage();
}

mkdir("/var/spool/keytabs", 022);
chmod(0755, "/var/spool/keytabs");
die "/var/spool/keytabs does not exist or isn't readable"
    if ! -d "/var/spool/keytabs";

my $lockdir = "/var/run/krb5_keytab";
my $lockfile = "$lockdir/lock.proid.$proid";

#
# Setup the umask.  This is important.  We assume that we have a
# reasonable umask later in the program.

umask(0077);

eval {
	#
	# Now we need to serialise our calls as well as create a tmp
	# keytab with the original keytabs contents for modification.
	# As we will be removing keys and then adding them, we need to
	# do this in a scratch location:

	obtain_lock($lockdir, $lockfile);

	#
	# Okay, now we have our lock we are protected:

	$errs += install_all_keys($proid, $kmdb, $action, $krb5_lib, @princs);
	$errs += test_keytab($proid, $krb5_lib, @princs);
};

if ($@) {
	syslog('err', "Received error from action %s, %s", $action,
	    format_err($@));
	print STDERR (format_err($@) . "\n");
	print STDERR "Failed\n";
}

#
# This system($KDESTROY) may not be run in all cases.  We should refactor
# the code quite a bit to ensure that it does make it.
system($KDESTROY);
if ($errs == 1) {
	syslog('err', "%s generated from %s's keytab resulting in 1" .
	    " error", $invoking_user, $proid);
	print STDERR "1 error was encountered.\n";
	exit(1);
}
if ($errs > 0) {
	syslog('err', "%s generated from %s's keytab resulting in %d" .
	    " errors", $invoking_user, $proid, $errs);
	print STDERR "$errs errors were encountered.\n";
	exit(1);
}
syslog('info', "%s generated from %s's keytab successfully",
    $invoking_user, $proid);
vprint "No errors were encountered.\n";
exit(0);
