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

use Krb5Admin::Client;
use Krb5Admin::KerberosDB;
use Krb5Admin::Utils qw/host_list/;
use Krb5Admin::C;

# XXXrcd: just for testing:
use Data::Dumper;

use strict;
use warnings;

#
# Constants:

our $KRB5_KEYTAB_CONFIG = '@@KRB5_KEYTAB_CONF@@';
our $KLIST    = '@@KLIST@@';
our $KINIT    = '@@KINIT@@';
our @KINITOPT = qw(@@KINITOPT@@ -l 10m);
our $KDESTROY = '@@KDESTROY@@';

#
# These variables are expected to be set in the configuration file:

our %user2service = ();
our @allowed_enctypes = ();
our @admin_users = ();
our %krb5_libs = ();
our %krb5_lib_quirks = ();
our $default_krb5_lib = ();
our %user_libs = ();
our $use_fetch = 0;

#
# Done: config file.

#
# And we define a few lookup tables:

our %enctypes = (
	0x12	=> 'aes256-cts',
	0x11	=> 'aes128-cts',
	0x17	=> 'rc4-hmac',
	0x10	=> 'des3-cbc-sha1',
	0x01	=> 'des-cbc-crc',
	0x03	=> 'des-cbc-md5',
);
our %revenctypes;
for my $i (keys %enctypes) {
	$revenctypes{$enctypes{$i}} = $i;
}
our $bootetype_name = "aes256-cts";
our $bootetype_code = $revenctypes{$bootetype_name};

BEGIN {
	my ($fh, $ccname) = mkstemp("/tmp/krb5_keytab_ccXXXXXX");
	undef($fh);
	our $krb5ccname = "FILE:$ccname";
	$ENV{KRB5CCNAME} = $krb5ccname;
}

END {
	local($?);
	system($KDESTROY);
}

#
# And our global variables:

our $ctx;
our $krb5ccname;
our $defrealm;
our $defkt = "/etc/krb5.keytab";
our $instances;
my  $hostname = hostname();
our @hostinsts = ();
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

sub get_ugid {
	my @pwd = getpwnam($_[0]);

	die "can't determine uid for $_[0]" if @pwd < 9;

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
	! scalar(grep { $_ =~ m{^aes[12]} } @_) ||
	  scalar(grep { $_ =~ m{^des-cbc-} } @_);
}

sub lib_requires_admin {
	enctypes_require_admin(@{$krb5_libs{$_[0]}});
}

sub lib_better {
	my ($a, $b) = @_;
	my @a = grep { $_ !~ m{^des-cbc-} } @{$krb5_libs{$a}};
	my @b = grep { $_ !~ m{^des-cbc-} } @{$krb5_libs{$b}};

	return  1	if is_subset(\@a, \@b);
	return -1	if is_subset(\@b, \@a);
	return scalar(@b) <=> scalar(@a);
}

sub sort_libs { sort { lib_better($a, $b) } @_; }

sub max_kvno {
	my $kvno = -1;
	for my $i (@{$_[0]}) {
		$kvno = $i->{kvno}	if $i->{kvno} > $kvno;
	}
	return $kvno;
}

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

sub parse_princ {
	my ($princ) = @_;

	if (!defined($princ)) {
		die "parse_princ called without an argument.";
	}

	return Krb5Admin::C::krb5_parse_name($ctx, $princ);
}


# XXXrcd: maybe we should perform a little validation later.
# XXXrcd: also lame because it is code duplication.
sub unparse_princ {
	my ($realm, @comps) = @{$_[0]};

	return join('/', @comps) . '@' . $realm;
}

#
# Munge the output of Krb5Admin::C::read_kt into something
# that is a little easier for me to deal with:

sub get_keys {
	my ($kt) = @_;

	$kt = "FILE:$defkt" if !defined($kt) || $kt eq '';
	my @ktkeys = Krb5Admin::C::read_kt($ctx, $kt);

	for my $i (@ktkeys) {
		$i->{enctype} = $enctypes{$i->{enctype}};
	}
	@ktkeys;
}

#
# Delete a principal (all keys) from a keytab file.

sub del_kt_princ {
	my ($strprinc, $kt) = @_;

	$kt = "WRFILE:$defkt" if !defined($kt) || $kt eq '';
	my @ktents = Krb5Admin::C::read_kt($ctx, $kt);

	for my $ktent (@ktents) {
		next if ($ktent->{"princ"} ne $strprinc);
		Krb5Admin::C::kt_remove_entry($ctx, $kt, $ktent)
	}
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
	my ($realm) = @_;
	my @tmp;
	my %ret;

	@tmp = map { [ parse_princ($_->{princ}) ] } (get_keys(''));

	for my $i (grep { $_->[1] eq 'host' && $_->[0] eq $realm } @tmp) {
		$ret{$i->[2]} = 1;
	}
	keys %ret;
}

#
# expand_princs takes an array ref representing a single princ and
# returns a list of said array refs.  The expansion is:
#
#	1.  populate the realm if not specified,
#
#	2.  if the instance is not specified then generalise from
#	    the global var @instances which is derived from
#	    /etc/krb5.keytab.  After all, this _is_ the maximal
#	    set that we could ever hope to fetch.

sub expand_princs {
	my ($pr) = @_;
	my @insts;
	my $realm;

	$realm = $pr->[0];
	if (!defined($realm) || $realm eq '') {
		if (!defined($defrealm)) {
			$defrealm = Krb5Admin::C::krb5_get_realm($ctx);
		}

		$realm = $defrealm;
	}

	if (!defined($pr->[2]) || $pr->[2] eq '') {
		if ($pr->[1] eq 'host') {
			@hostinsts = host_list($hostname) if @hostinsts == 0;
			@insts = @hostinsts;
		} else {
			if (!exists($instances->{$realm}) ||
			    @{$instances->{$realm}} == 0) {
				$instances->{$realm} = [get_instances($realm)];
			}
			@insts = @{$instances->{$realm}};
		}
	} else {
		@insts = ($pr->[2]);
	}

	return map { [ $realm, $pr->[1], $_ ] } @insts;
}


#
# check_acls takes a single user and a list of principals specified
# as listrefs: [ REALM, name, instance ] and will exit if the requested
# operation is disallowed.
#
# This only checks if the user's keytab is allowed to contain the service
# principals requested and is used to allow, e.g. imapsvr to install keys
# for imap/hostname@REALM into /var/spool/keytabs/imapsvr if you are running
# your imap servers as the imapsvr user in your environment.
#
# Okay.  Now, we have a list of array refs representing the requested
# principals.  We need to do a little sanity checking on the data.  What
# we're doing here is a tad odd from first sight, but the configuration
# file contains a variable %user2service which is a hash which keys on
# the user.  The value is an array ref of services which the user is
# allowed to request in its keytabs.  We extract this array ref and turn
# it into a hash so that it can be used as a constant time lookup in the
# grep.  We also add $user to the hash for good measure as we implicitly
# allow the user to request keys for the service of the same name...

sub check_acls {
	my ($user, @services) = @_;
	my $err;

	return if $user eq 'root';

	our %acl_svcs;
	$user2service{$user} = [$user] if !defined($user2service{$user});
	%acl_svcs = map { $_ => 1 } @{$user2service{$user}};

	for my $i (grep { !defined($acl_svcs{$_->[1]}) } @services) {
		print STDERR "Permission denied: $user can't create " .
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
# get_kt() determines the location of the keytab based on the user on
# which we are operating.

sub get_kt {
	my ($user) = @_;

	return "WRFILE:/var/spool/keytabs/$user" if $user ne 'root';
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
	my ($user) = @_;
	my @keys = get_keys(get_kt($user));
	my @princs = get_princs(@keys);

	print "Keytab contains " . scalar(@princs) . " principals\n";

	for my $i (@princs) {
		print "\n\nPrincipal $i can work with the following\n";
		print "Kerberos libraries:\n\n";

		pretty_print_libs(\*STDOUT, supports_libs($i, @keys));
	}
}

sub test_keytab {
	my ($user, $lib, @inprincs) = @_;
	my @keys = get_keys(get_kt($user));
	my @princs = get_princs(@keys);
	my $err = 0;

	$lib = $default_krb5_lib if !defined($lib);

	for my $i (map { unparse_princ($_) } @inprincs) {
		if ($i =~ m{^bootstrap/RANDOM}) {
			vprint "Not testing $i\n";
			next;
		}
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
	my ($user, @inprincs) = @_;
	my @keys = get_keys(get_kt($user));
	my @princs = get_princs(@keys);
	my @errs;
	my $err = 0;

	for my $i (@inprincs) {
		if (!in_set($i, [@princs])) {
			push(@errs, "$i does not exist in the keytab.\n");
			next;
		}
		my $working_lib = working_lib($i, @keys);

		if (!defined($working_lib) || (exists($user_libs{$user}) &&
		    !in_set($working_lib, $user_libs{$user}))) {
			$working_lib = $user_libs{$user}->[0];
		}

		if (!defined($working_lib)) {
			push(@errs, "Can't determine library for $i.\n");
			next;
		}

		print "krb5_keytab -p $user -L " . $working_lib . " $i\n";
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

	my @ktkeys;
	eval { @ktkeys = Krb5Admin::C::read_kt($ctx, $kt); };

	if ($@ || !grep { $_->{princ} eq $key } @ktkeys) {
		return 1;
	}

	# Avoid spawning shells, ignore stderr and stdout.
	#
	my $pid = fork();
	return 1 if ! defined($pid); # Can't fork
	if ($pid == 0) {
		open(STDOUT, ">/dev/null");
		open(STDERR, ">&STDOUT");
		exec { $KINIT } $KINIT, @KINITOPT,
			"-cMEMORY:foo", "-kt", "$kt", "$key";
		exit 1;
	}
	waitpid($pid, 0);
	return 1 if ($? != 0);
	return 0;
}

sub mk_keys	{
	map {Krb5Admin::C::krb5_make_a_key($ctx, $_)} @_;
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

		Krb5Admin::C::write_kt($ctx, $kt, $i);
	}
	vprint "Finished writing keys in write_keys_internal...\n";
}

sub write_keys_kt {
	my ($user, $lib, $princ, $kvno, @keys) = @_;
	my $oldkt;
	my $kt = get_kt($user);

	for my $i (@keys) {
		$i->{princ} = $princ	if defined($princ);
		$i->{kvno}  = $kvno	if defined($kvno);
	}

	write_keys_internal($ctx, $lib, $kt, @keys);

	my @ktkeys;
	eval { @ktkeys = Krb5Admin::C::read_kt($ctx, $kt); };

	return if $force < 2 && !is_quirky($lib, @ktkeys);

	vprint "Recreating keytab file fixing quirks...\n";

	$oldkt = $kt;
	$oldkt =~ s/WRFILE://;
	unlink("$oldkt.tmp");
	$kt = "WRFILE:$oldkt.tmp";
	@keys = ktuniq(@ktkeys, @keys);

	write_keys_internal($ctx, $lib, $kt, @keys);

	$kt =~ s/^WRFILE://;
	chmod(0400, $kt)		or die "chmod: $!";
	chown(get_ugid($user), $kt)	or die "chown: $!";
	rename($kt, $oldkt)		or die "rename: $!";

	vprint "New keytab file rename(2)ed into position, quirk-free\n";
}

sub install_key {
	my ($kmdb, $action, $lib, $client, $user, $princ) = @_;
	my $strprinc = unparse_princ($princ);
	my $kt = get_kt($user);
	my $ret;
	my $etypes;

	if (!$kmdb) {
		die "Cannot connect to KDC.";
	}

	$etypes = $krb5_libs{$lib} if defined($lib);

	if ($action ne 'change' && $force < 1) {
		return 0 if !need_new_key($kt, $strprinc);
	}

	$kmdb->master()		if $action eq 'change';

	vprint "installing: $strprinc\n";

	my $func = $kmdb->can('change');
	eval { $ret = $kmdb->query($strprinc) };
	my $err = $@;
	if ($err) {
		die $err if $action ne 'default';
		vprint "query error: " . format_err($err) . "\n";
		vprint "creating: $strprinc\n";

		$func = $kmdb->can('create');
	}

	#
	# Now, in this mode, we cannot simply fetch the keys and
	# so, well, we will see if we are up to date.
	#
	# XXXrcd: If we aren't, well, the best thing that we can
	#         do is either toss an exception or just warn and
	#         change the keys.  For now, we die, if the instance
	#         is not the system fqdn (hostname is assumed to be
	#         an fqdn). For other instances, we abort, as the
	#         key may be shared among the members of a cluster.

	if (!$err && $action eq 'default') {
		my @ktkeys;
		eval { @ktkeys = Krb5Admin::C::read_kt($ctx, $kt); };
		@ktkeys = grep { $_->{"princ"} eq $strprinc } @ktkeys;

		if (max_kvno(\@ktkeys) < max_kvno($ret->{keys})) {
			#
			# If the instance matches the local hostname,
			# just change the key, it should not be shared
			# with other hosts.

			if ($princ->[2] ne $hostname) {
				die "The kvno for $strprinc is less than".
				    " the KDCs, aborting as the key may".
				    " be shared with other hosts. If the".
				    " is not shared, you may use $0 -c".
				    " to force a key change.\n";
			}
			$action = 'change';
		} else {
			vprint "The keys for $strprinc already exist.\n";
			return 0;
		}
	}

	my $kvno = 0;
	my @kvno_arg = ();
	if ($action eq 'change') {
		# Find the max kvno:
		$kvno = max_kvno($ret->{keys});
		die "Could not determine max kvno" if $kvno == -1;
		@kvno_arg = ($kvno + 1);
	}

	if (!defined($etypes) && $action eq 'change') {
		my %enctypes;

		for my $i (grep {$_->{kvno} == $kvno} @{$ret->{keys}}) {
			$enctypes{$i->{enctype}}=1;
		}
		$etypes = [ keys %enctypes ];
	}

	if (!defined($etypes)) {
		$etypes = $krb5_libs{$default_krb5_lib};
		$etypes = [map { $revenctypes{$_} } @$etypes];
	}
	my $gend = $kmdb->genkeys($strprinc, $kvno + 1, @$etypes);
	write_keys_kt($user, $lib, undef, undef, @{$gend->{'keys'}});
	&$func($kmdb, $strprinc, @kvno_arg, 'public' => $gend->{'public'},
	    'enctypes' => $etypes);
}

sub install_key_legacy {
	my ($kmdb, $action, $lib, $client, $user, $princ) = @_;
	my $strprinc = unparse_princ($princ);
	my $kt = get_kt($user);
	my @ret;
	my $etypes;

	if (!$kmdb) {
		die "Cannot connect to KDC.";
	}

	$etypes = $krb5_libs{$lib} if defined($lib);

	if ($action ne 'change' && $force < 1) {
		return 0 if !need_new_key($kt, $strprinc);
	}

	vprint "installing (legacy): $strprinc\n";

	$kmdb->master()		if $action eq 'change';

	eval { @ret = $kmdb->fetch($strprinc) };
	if ($@) {
		die $@ if $action ne 'default';
		vprint "fetch error: " . format_err($@) . "\n";
		vprint "creating: $strprinc\n";
		eval {
			$kmdb->create($strprinc);
			if (defined($etypes)) {
				$kmdb->change($strprinc, -1,
				    [mk_keys(@$etypes)]);
			}
		};
		if ($@) {
			vprint "creation error: ".format_err($@)."\n";
		}
		@ret = $kmdb->fetch($strprinc);
	}

	write_keys_kt($user, $lib, $strprinc, undef, @ret);

	return if $action ne 'change';

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
	write_keys_kt($user, $lib, $strprinc, $kvno, @keys);
	$kmdb->change($strprinc, $kvno, \@keys);
}

sub bootstrap_host_key {
	my ($kmdb, $action, $lib, $client, $user, $princ) = @_;
	my $strprinc = unparse_princ($princ);
	my $realm = $princ->[0];

	vprint "bootstrapping a host key.\n";

	#
	# If we are here, then we've decided that we are bootstrapping
	# which means that we need to obtain credentials for a bootstrap
	# principal of the form bootstrap/*@REALM.  We find one and try
	# it.  If it fails to connect, we try another one.  We presume
	# that we're failing because the princ doesn't exist in the KDC
	# but perhaps we should test the result of Krb5Admin::Client->new()
	# to see if there was another reason...

	my $bootprinc;
	foreach my $ktent (get_keys()) {
		# Ignore bootstrap keys with an unexpected enctype.
		next if ($ktent->{"enctype"} ne $bootetype_name);
		my ($r, $n) = parse_princ($bootprinc = $ktent->{"princ"});
		next if ($r ne $realm || $n ne 'bootstrap');

		vprint "Trying to connect with $bootprinc creds.\n";
		if (!defined($kmdb)) {
			eval {
				$kmdb = Krb5Admin::Client->new($bootprinc,
				    { realm => $realm });
				$kmdb->master();
			};
			if ($@) {
				vprint "$bootprinc failed to connect" .
				    " to a KDC for $realm: " .
				    format_err($@) . "\n";
			}
		}

		last if defined($kmdb);
	}

	if (!defined($kmdb)) {
		die "Can not connect to KDC.";
	}

	vprint "Connected.\n";

	my $ret;
	eval { $ret = $kmdb->query($strprinc) };
	my $err = $@;
	if ($err) {
		die $err if $action ne 'default';
		vprint "query error: " . format_err($err) . "\n";
		vprint "creating: $strprinc\n";
	}

	my $kvno = 0;
	$kvno = max_kvno($ret->{keys})		if defined($ret);

	#
	# XXX: With etype aliases in Heimdal, may not need the rev map...

	my $etypes = $krb5_libs{$lib} if defined($lib);
	if (!defined($etypes)) {
		$etypes = $krb5_libs{$default_krb5_lib};
	}
	$etypes = [map { $revenctypes{$_} } @$etypes];

	my $gend = $kmdb->genkeys($strprinc, $kvno + 1, @$etypes);
	write_keys_kt($user, $lib, undef, undef, @{$gend->{keys}});
	eval {
		$kmdb->bootstrap_host_key($strprinc, $kvno + 1,
		    public => $gend->{public}, enctypes => $etypes);

		#
		# The KDC deleted the bootstrap principal, so we do
		# likewise, but ignore errors, we got the main job done!

		eval { del_kt_princ($bootprinc); };
	};

	#
	# SUCCCESS!

	return 0 if !$@;

	vprint "bootstrapping host key failed: ". format_err($@) ."\n";

	#
	# so, if we failed then perhaps we do not have
	# permissions?  If this is the case, then, well,
	# we're connected to the KDC already, we can simply
	# ask it what we need to do to make progress.

	$ret = $kmdb->query_host(name => $princ->[2]);

	if (!defined($ret)) {
		die "Cannot determine the host's bootbinding.";
	}

	if (!defined($bootprinc = $ret->{bootbinding})) {
		die "$strprinc is not bound to any bootstrap id.";
	}

	vprint "host is actually bound to " . $bootprinc . "\n";

	$kmdb = Krb5Admin::Client->new($bootprinc, {realm => $realm});

	vprint "Connected as " . $bootprinc . "\n";

	$gend = $kmdb->genkeys($strprinc, $kvno + 1, $bootetype_code);
	write_keys_kt($user, $lib, undef, undef, @{$gend->{keys}});
	$kmdb->bootstrap_host_key($strprinc, $kvno + 1,
	    public => $gend->{public}, enctypes => $etypes);
	eval { del_kt_princ($bootprinc); };
}

sub install_host_key {
	my ($kmdb, $action, $lib, $client, $user, $princ) = @_;
	my $f;

	#
	# host keys are just a little different than service keys.
	# If we have host credentials, then we may very well just
	# be able to use them.  If not, we must be bootstrapping and
	# we call bootstrap_host_key() which is a tad more complex.

	$f = \&install_key;
	$f = \&install_key_legacy	if $use_fetch;

	if ($kmdb) {
		#
		# XXXrcd: should we fail here or should we continue
		#         to the bootstrapping code because we may
		#         have lost our association with the KDC?

		return &$f(@_);
	}

	return bootstrap_host_key(@_);
}

sub install_bootstrap_key {
	my ($kmdb, $action, $lib, $client, $user, $princ) = @_;
	my $realm = $princ->[0];

	vprint "installing a bootstrap key.\n";

	if (!defined($kmdb)) {
		vprint "obtaining anonymous tickets.\n";
		# The default realm may not vend anon tickets, use the
		# target realm!
		#
		system {$KINIT} ($KINIT, @KINITOPT, '--anonymous', $realm);

		vprint "connecting to $realm\'s KDC.\n";
		$kmdb = Krb5Admin::Client->new(undef, { realm => $realm });
	}

	my $gend = $kmdb->genkeys('bootstrap', 1, $bootetype_code);
	my $binding = $kmdb->create_bootstrap_id(public => $gend->{public},
	    enctypes => [$bootetype_code], realm => $realm);
	$gend = $kmdb->regenkeys($gend, $binding);

	write_keys_kt($user, undef, undef, undef, @{$gend->{keys}});

	# We must output the binding so that applications know what it is.
	print $binding . "\n";
}

#
# install_keys is a dispatcher that determines what to do with each
# key.  It will [optionally] create a connexion to krb5_admind ($kmdb)
# and dispatch to one of the functions that takes care of the particular
# kind of key that we want.  install_keys expects to be called with
# @princs being a list of parsed krb5 princs which have the same realm
# and instance.  It will either toss an exception if something goes
# horribly wrong or return an integral number of errors that were
# encountered.

sub install_keys {
	my ($user, $kmdb, $got_tickets, $xrealm, $action, $lib, @princs) = @_;
	my $realm = $princs[0]->[0];
	my $inst  = $princs[0]->[2];
	my $client;
	my $errs = 0;
	my $bootstrapping = 0;

	if (!$got_tickets) {
		$client = unparse_princ([defined($xrealm) ? $xrealm : $realm,
		    "host", $inst]);
	}

	if (!defined($kmdb)) {
		my $str = "";

		$str .= "connecting to $princs[0]->[0]'s KDCs";
		if (defined($client)) {
			$str .= " using $client creds.";
		}
		vprint "$str\n";
		eval {
			$kmdb = Krb5Admin::Client->new($client,
			    { realm => $realm });
		};

		vprint "Cannot connect to KDC: " . format_err($@) . "\n";
	}

	for my $princ (@princs) {
		my $strprinc = unparse_princ($princ);

		vprint "Focussing on $strprinc.\n";

		my $f = \&install_key;

		$f = \&install_key_legacy	if $use_fetch;
		$f = \&install_host_key		if $princ->[1] eq 'host';

		if ($princ->[1] eq 'bootstrap' && $princ->[2] eq 'RANDOM') {
			$f = \&install_bootstrap_key;
		}

		eval {
			&$f($kmdb, $action, $lib, $client, $user, $princ);
		};
		if ($@) {
			print STDERR (format_err($@) . "\n");
			print STDERR "Failed to install keys: $strprinc\n";
			syslog('err', "Failed to install (%s) keys for %s " .
			    "instance %s, %s", $action, $user,
			    $strprinc, format_err($@));
			$errs++;
		} else {
			syslog('info', "Installed (%s) keys for %s " .
			    "instance %s", $action, $user, $strprinc);
		}
	}

	return $errs;
}

#
# install_all_keys just takes:
#
#	1.  the keytab location,
#
#	2.  the user, and
#
#	3.  a simple list of principals which are represented by
#	    listrefs [ REALM, service, instance ].  It breaks up
#	    the requests into groups with like instances and calls
#	    install_keys().
#
# It works by building a hash of instance => [ princs ] and iterating
# over the keys of that map calling install_keys.

sub install_all_keys {
	my ($user, $kmdb, $got_tickets, $xrealm, $action, $lib, @princs) = @_;
	my %instmap;
	my $kt = get_kt($user);
	my $errs = 0;

	vprint "checking acls...\n";
	check_acls($user, @princs);		# this will exit on failure.

	for my $i (@princs) {
		push(@{$instmap{$i->[0]}->{$i->[2]}}, $i);
	}

	my @connexions;
	for my $realm (keys %instmap) {
		for my $inst (keys %{$instmap{$realm}}) {
			push(@connexions, [$realm, $inst,
			    $instmap{$realm}->{$inst}]);
		}
	}

	my $instkeys = \&install_key;
	if ($use_fetch) {
		$instkeys = \&install_key_legacy;
	}

	for my $i (@connexions) {
		vprint "installing keys for connexion $i->[0], $i->[1]...\n";

		$errs += install_keys($user, $kmdb, $got_tickets, $xrealm,
		    $action, $lib, @{$i->[2]});
	}

	$kt =~ s/^WRFILE://;
	chmod(0400, $kt)		or die "chmod: $!";
	chown(get_ugid($user), $kt)	or die "chown: $!";

	vprint "Successfully updated keytab file\n" if $errs == 0;
	return $errs;
}

#
# Cmd line syntax:

sub usage {

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

	my @self_service = grep { ! lib_requires_admin($_) } (keys %krb5_libs);
	pretty_print_libs(\*STDERR, sort_libs(@self_service));

	print STDERR <<EOM;

The following libraries are only supported by administrators:

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

$ctx = Krb5Admin::C::krb5_init_context();

our %opts;
my $errs = 0;
my $action;
my $kmdb;
my $got_tickets = 0;
my %admin_users;
my $krb5_lib;
my $xrealm;

%admin_users = map { $_ => 1 } @admin_users;

# XXXrcd: getopt error?
getopts('AFL:RW:X:Zcfglqp:rtu:vw?', \%opts) or usage();

usage() if defined($opts{'?'});

my $invoking_user = $opts{u};
if (!defined($invoking_user)) {
	print STDERR "Improperly invoked, must use wrapper.\n";
	exit(1);
}

my $user = $opts{p};
if (!defined($user)) {
	$user = $invoking_user;
}
if (!defined(getpwnam($user))) {
	print STDERR "User ID $user does not exist.\n";
	exit(1);
}

if ($invoking_user ne $user && $invoking_user ne 'root' &&
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

$verbose = 1		if defined($opts{v});
$force   = 1		if defined($opts{f});
$force   = 2		if defined($opts{F});
$xrealm  = $opts{X}	if defined($opts{X});
$action  = 'default';
$action  = 'change'	if defined($opts{c});
$action  = 'list'	if defined($opts{l});
$action  = 'query'	if defined($opts{q});
$action  = 'test'	if defined($opts{t});
$action  = 'generate'	if defined($opts{g});

if (defined($opts{w}) && defined($opts{W})) {
	die "-W and -w are mutally exclusive.\n";
}

if (defined($opts{w}) && !defined($opts{X})) {
	die "specifying -w requires -X.\n";
}

if ((defined($opts{W}) || defined($opts{X})) && defined($opts{A})) {
	die "-A may not be specified with either -W or -X.\n";
}

if (scalar(@ARGV) == 0) {
	@ARGV = ($user);
	@ARGV = ('host')  if $user eq 'root';
}

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
if (defined($opts{A}) || defined($opts{Z})) {
	if ($invoking_user ne 'root' && !$admin_users{$invoking_user}) {
		die "-A and -Z require administrative access.";
	}
}

if (defined($opts{A}) && !defined($opts{Z})) {
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

		system($KINIT, @KINITOPT, $admin) and next;
		$got_tickets = 1;
		last;
	}
} elsif (defined($opts{Z})) {
	$kmdb = Krb5Admin::KerberosDB->new(local => 1);
}

if (defined($opts{W}) || defined($opts{w})) {
	my @princs;

	if (defined($opts{W})) {
		@princs = ($opts{W});
	}

	if (defined($opts{w})) {
		my %hashprincs;

		%hashprincs = map { $_->{princ} => 1 } (get_keys(''));
		@princs = map { [ parse_princ($_) ] } (keys %hashprincs);
		@princs = grep { $_->[0] eq $opts{X} } @princs;
		@princs = grep { $_->[1] =~ /\$$/o } @princs;
		@princs = grep { !defined($_->[2]) } @princs;

		if (@princs == 0) {
			die "Can't find any principals in realm " .
			    $opts{X} . " which end in a buck (\$).\n";
		}

		@princs = map { unparse_princ($_) } @princs;
	}

	my $ret;
	for my $princ (@princs) {
		$ret = system($KINIT, '-k', @KINITOPT, $princ);

		last if $ret == 0;
		print STDERR "Warning: Could not obtain tickets for $princ.\n";
	}

	if ($ret) {
		die "could not obtain creds for any windows principal.\n";
	}
	$got_tickets = 1;
}

@princs = map { expand_princs([ parse_princ($_) ]) } @ARGV;

#
# XXXrcd: this all needs to be refactored.

if ($action eq 'list') {
	if (!$admin_users{$invoking_user}) {
		syslog('err', "%s attempted to list %s's keytab",
		    $invoking_user, $user);
		die "list is an administrative function only.";
	}
	syslog('info', "%s listed %s's keytab", $invoking_user, $user);
	system $KLIST ($KLIST, '-ekt', get_kt($user));
	exit(0);
}

if ($action eq 'query') {
	syslog('info', "%s queried %s's keytab", $invoking_user, $user);
	query_keytab($user);
	exit(0);
}

if ($action eq 'generate') {
	$errs += generate_keytab($user, map {unparse_princ($_)} @princs);

	if ($errs == 1) {
		syslog('err', "%s generated from %s's keytab resulting in 1" .
		    " error", $invoking_user, $user);
		print STDERR "1 error was encountered.\n";
		exit(1);
	}
	if ($errs > 0) {
		syslog('err', "%s generated from %s's keytab resulting in %d" .
		    " errors", $invoking_user, $user, $errs);
		print STDERR "$errs errors were encountered.\n";
		exit(1);
	}
	syslog('info', "%s generated from %s's keytab successfully",
	    $invoking_user, $user);
	vprint "No errors were encountered.\n";
	exit(0);
}

#
# This test occurs after all the non-change options:

my $real_krb5_lib = $default_krb5_lib;
$real_krb5_lib = $krb5_lib if defined($krb5_lib);
if (defined($real_krb5_lib) && exists($user_libs{$user}) &&
    !in_set($real_krb5_lib, $user_libs{$user})) {
	print STDERR "$user does not support $real_krb5_lib.\n";
	exit(1);
}

if ($action eq 'test') {
	$errs += test_keytab($user, $krb5_lib, @princs);

	if ($errs == 1) {
		syslog('err', "%s tested %s's keytab against %s resulting in ".
		    "1 error", $invoking_user, $user, $real_krb5_lib);
		print STDERR "1 error was encountered.\n";
		exit(1);
	}
	if ($errs > 0) {
		syslog('err', "%s tested %s's keytab against %s resulting in ".
		    "%d errors", $invoking_user, $user, $real_krb5_lib, $errs);
		print STDERR "$errs errors were encountered.\n";
		exit(1);
	}
	syslog('info', "%s tested %s's keytab against %s successfully",
	    $invoking_user, $user, $real_krb5_lib);
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
my $lockfile = "$lockdir/lock.user.$user";

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

	$errs += install_all_keys($user, $kmdb, $got_tickets, $xrealm,
	    $action, $krb5_lib, @princs);
	$errs += test_keytab($user, $krb5_lib, @princs);
};

if ($@) {
	my $err = $@;

	syslog('err', "Received error from action %s, %s", $action,
	    format_err($err));
	print STDERR (format_err($err) . "\n");
	print STDERR "Failed\n";
	exit(1);
}

if ($errs == 1) {
	syslog('err', "%s generated from %s's keytab resulting in 1" .
	    " error", $invoking_user, $user);
	print STDERR "1 error was encountered.\n";
	exit(1);
}
if ($errs > 0) {
	syslog('err', "%s generated from %s's keytab resulting in %d" .
	    " errors", $invoking_user, $user, $errs);
	print STDERR "$errs errors were encountered.\n";
	exit(1);
}
syslog('info', "%s generated from %s's keytab successfully",
    $invoking_user, $user);
vprint "No errors were encountered.\n";
exit(0);
