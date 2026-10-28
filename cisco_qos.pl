#!/usr/bin/perl
#Class-based weighted fair queue interrogation module.
#This module maps class names to policy-id, object-id pairs and
#does an SNMP get on the bytes transmitted OID.
#written by Andy Brauer
#initial release 07/05/2002
#current release 26/04/2005
#current version 0.53
#
# 25/04/2005 - Paul Wozney
#
# Completely rewritten by Paul Wozney
# There was nothing really wrong with the script that Andy wrote,
# but I extended it to respond to index, query and get requests
# and made seperate subroutines for these
#
# current version 0.54
# 23/7/0/5 - Nitzan Tzelniker
# This time I change the script so it can monitor class with the same name on diferent interfaces
# I remove the filterstring because I dont need it.
# It run much faster when it get the output because it only snmpget one value not snmpwalk few times.
# it need more developmant if we want it will look beter but it work for me.
# it can also monitor drop rate of the class-map just add new graph template and change your xml.
# the current data query should work with this script but backup you you DB before you change the script because it come without any warranty
# send any bugs and suggestions to nitzan.tzelniker@gmail.com
#
# 11/2/2010 - Eugene Filatov (efilatov at gmail.com)
# The script was not able to grab indexes for classes on my cacti (v0.8.7b) and for this reason it was not able to create graphs.
# Data Query was splted into 4 parts - Index, Interface, Policy-map and Class.
# There is still one bug which I was not able to fix - script is not able to build the relations in case class-default is a parent for policy-map.
# It seems that the bug is related to cisco SNMP which is not able to provide proper parent-child relations in this case.
#
# 28/10/2026 - version 0.60, for Cacti 1.2
# - SNMP v1, v2c and v3. The data query passes every SNMP setting of the device
#   (see cisco_qos.xml), so the script uses whatever the device is configured with.
#   Settings arrive as key=value: Cacti drops empty arguments from the command
#   line, which would shift positional ones (e.g. a v3 device's blank community).
# - net-snmp is run without a shell, so passwords and communities containing
#   $ ! ' etc. are passed through safely.
# - Classes are tied to their policy-map through cbQosParentObjectsIndex instead
#   of walk order. This fixes the 2010 bug above: classes of a child policy
#   nested under class-default are reported under the child policy-map.
# - Drops use cbQosCMDropByte64 (was the 32-bit cbQosCMDropByte). Bytes already
#   used cbQosCMPostPolicyByte64.
# - Class, policy-map and interface names containing spaces are no longer cut
#   at the first space.
# - Index values (policy index.object index) are unchanged, so existing data
#   sources keep working.

use strict;
use warnings;

my $usage = <<'EOT';
usage:
  cisco_qos.pl host=HOST ver=1|2|3 [comm=..] [user=..] [authpw=..] [authproto=..]
               [privpw=..] [privproto=..] [context=..] [engine=..] [port=..] [timeout=MS] ACTION

  ACTION:  index
           num_indexes
           query {index|interface|policymap|class|all}
           get {bytes|drops} INDEX

  The data query's <arg_prepend> (cisco_qos.xml) passes every setting as key=value.
  Cacti drops empty arguments, so values are never passed bare.
EOT

my %opt;
while (@ARGV && $ARGV[0] =~ /^(host|ver|comm|user|authpw|authproto|privpw|privproto|context|engine|port|timeout)=(.*)$/s) {
	$opt{$1} = $2;
	shift @ARGV;
}
die $usage unless defined $opt{host} && $opt{host} ne '' && @ARGV;

my $host       = $opt{host};
my $version    = defined $opt{ver}       ? $opt{ver}       : '2';
my $comm       = defined $opt{comm}      ? $opt{comm}      : '';
my $user       = defined $opt{user}      ? $opt{user}      : '';
my $auth_pass  = defined $opt{authpw}    ? $opt{authpw}    : '';
my $auth_proto = defined $opt{authproto} ? $opt{authproto} : '';
my $priv_pass  = defined $opt{privpw}    ? $opt{privpw}    : '';
my $priv_proto = defined $opt{privproto} ? $opt{privproto} : '';
my $context    = defined $opt{context}   ? $opt{context}   : '';
my $engine_id  = defined $opt{engine}    ? $opt{engine}    : '';
my $port       = defined $opt{port}      ? $opt{port}      : '';
my $timeout_ms = defined $opt{timeout}   ? $opt{timeout}   : '';

my ($action1, $action2, $theindex) = @ARGV;
$action2  = '' unless defined $action2;
$theindex = '' unless defined $theindex;

my $snmpwalk     = '/usr/bin/snmpwalk';
my $snmpbulkwalk = '/usr/bin/snmpbulkwalk';
my $snmpget      = '/usr/bin/snmpget';

# CISCO-CLASS-BASED-QOS-MIB
my $if_type_oid      = '.1.3.6.1.4.1.9.9.166.1.1.1.1.2';   # cbQosIfType             (policy)
my $if_index_oid     = '.1.3.6.1.4.1.9.9.166.1.1.1.1.4';   # cbQosIfIndex            (policy)
my $config_index_oid = '.1.3.6.1.4.1.9.9.166.1.5.1.1.2';   # cbQosConfigIndex        (policy.object)
my $object_type_oid  = '.1.3.6.1.4.1.9.9.166.1.5.1.1.3';   # cbQosObjectsType        (policy.object)
my $parent_oid       = '.1.3.6.1.4.1.9.9.166.1.5.1.1.4';   # cbQosParentObjectsIndex (policy.object)
my $policy_name_oid  = '.1.3.6.1.4.1.9.9.166.1.6.1.1.1';   # cbQosPolicyMapName      (config)
my $class_name_oid   = '.1.3.6.1.4.1.9.9.166.1.7.1.1.1';   # cbQosCMName             (config)
my $bytes_oid        = '.1.3.6.1.4.1.9.9.166.1.15.1.1.10'; # cbQosCMPostPolicyByte64 (policy.object)
my $drops_oid        = '.1.3.6.1.4.1.9.9.166.1.15.1.1.17'; # cbQosCMDropByte64       (policy.object)
my $ifname_oid       = '.1.3.6.1.2.1.31.1.1.1.1';          # ifName

my $TYPE_POLICYMAP       = 1;
my $TYPE_CLASSMAP        = 2;
my $IFTYPE_CONTROL_PLANE = 5;

my %auth_protos = (
	'MD5'    => 'MD5',
	'SHA'    => 'SHA',
	'SHA224' => 'SHA-224',
	'SHA256' => 'SHA-256',
	'SHA384' => 'SHA-384',
	'SHA512' => 'SHA-512',
);

# RHEL 10's net-snmp has no DES (OpenSSL 3) and no Cisco-style AES-192-C / AES-256-C.
my %priv_protos = (
	'AES'    => 'AES',
	'AES128' => 'AES',
	'AES192' => 'AES-192',
	'AES256' => 'AES-256',
);

my @snmp_opts = snmp_options();
my $target    = snmp_target();

sub fail {
	print STDERR "cisco_qos.pl: $_[0]\n";
	exit 1;
}

sub is_set {
	my $v = shift;
	return defined $v && $v ne '' && $v ne '[None]';
}

sub snmp_options {
	my @o;
	my $secs = ($timeout_ms =~ /^\d+$/ && $timeout_ms > 0) ? int(($timeout_ms + 999) / 1000) : 1;
	push @o, '-t', $secs, '-r', 2;

	if ($version eq '1' || $version eq '2') {
		push @o, '-v', ($version eq '1' ? '1' : '2c'), '-c', $comm;
	} elsif ($version eq '3') {
		fail('SNMPv3 username is empty') unless is_set($user);
		push @o, '-v', '3', '-u', $user;

		my $auth = is_set($auth_proto) && is_set($auth_pass);
		my $priv = $auth && is_set($priv_proto) && is_set($priv_pass);

		if ($auth) {
			my $a = $auth_protos{uc $auth_proto};
			fail("unsupported SNMPv3 auth protocol '$auth_proto'") unless $a;
			push @o, '-a', $a, '-A', $auth_pass;
		}
		if ($priv) {
			my $x = $priv_protos{uc $priv_proto};
			fail("unsupported SNMPv3 privacy protocol '$priv_proto' (use AES, AES-192 or AES-256)") unless $x;
			push @o, '-x', $x, '-X', $priv_pass;
		}
		push @o, '-l', ($priv ? 'authPriv' : $auth ? 'authNoPriv' : 'noAuthNoPriv');
		push @o, '-n', $context   if is_set($context);
		push @o, '-e', $engine_id if is_set($engine_id);
	} else {
		fail("SNMP version '$version' is not 1, 2 or 3");
	}

	# Numeric OIDs, values without type prefixes, enums as numbers.
	push @o, '-On', '-Oq', '-Oe';
	return @o;
}

sub snmp_target {
	my $p = ($port =~ /^\d+$/ && $port > 0) ? $port : 161;
	return $host if $host =~ /^(udp|tcp)6?:/i;           # transport already given
	return "udp6:[$host]:$p" if $host =~ /:/;            # IPv6 literal
	return "$host:$p";
}

# Run a net-snmp command without a shell. Returns the output lines.
sub run {
	my @cmd = @_;
	open(my $fh, '-|', @cmd) or fail("cannot run $cmd[0]: $!");
	my @out = <$fh>;
	close $fh;
	return @out;
}

# Strip net-snmp's quotes from a string value.
sub unquote {
	my $v = shift;
	$v =~ s/^\s+|\s+$//g;
	$v =~ s/^"(.*)"$/$1/s;
	$v =~ s/\\"/"/g;
	return $v;
}

# Walk $base. Returns { index-suffix => value }, the suffix without its leading dot.
sub walk {
	my $base = shift;
	my $cmd  = ($version eq '1') ? $snmpwalk : $snmpbulkwalk;
	my %r;
	foreach my $line (run($cmd, @snmp_opts, $target, $base)) {
		chomp $line;
		next unless $line =~ /^(\.?[\d.]+)\s+(.*)$/;
		my ($oid, $val) = ($1, $2);
		$oid = ".$oid" unless $oid =~ /^\./;
		next unless index($oid, "$base.") == 0;
		$r{substr($oid, length($base) + 1)} = unquote($val);
	}
	return \%r;
}

# Get several OIDs. Returns { oid => value } for the ones that exist.
sub get_many {
	my @oids = @_;
	my %r;
	while (my @chunk = splice(@oids, 0, 20)) {
		foreach my $line (run($snmpget, @snmp_opts, $target, @chunk)) {
			chomp $line;
			next unless $line =~ /^(\.?[\d.]+)\s+(.*)$/;
			my ($oid, $val) = ($1, $2);
			$oid = ".$oid" unless $oid =~ /^\./;
			next if $val =~ /^No Such (Instance|Object)/;
			$r{$oid} = unquote($val);
		}
	}
	return \%r;
}

# Cacti uses ! as the field delimiter.
sub clean {
	my $v = shift;
	$v = '' unless defined $v;
	$v =~ s/[!\r\n]+/_/g;
	return $v;
}

sub classes {
	my $if_index = walk($if_index_oid);
	my $if_type  = walk($if_type_oid);
	my $config   = walk($config_index_oid);
	my $type     = walk($object_type_oid);
	my $parent   = walk($parent_oid);
	my $pm_name  = walk($policy_name_oid);
	my $cm_name  = walk($class_name_oid);

	# Interface names for the interfaces that have a policy attached.
	my %ifidx = map { $_ => 1 } grep { /^\d+$/ && $_ > 0 } values %$if_index;
	my $names = get_many(map { "$ifname_oid.$_" } sort { $a <=> $b } keys %ifidx);

	my @rows;
	foreach my $key (keys %$type) {
		next unless $type->{$key} eq $TYPE_CLASSMAP;
		my ($pol, $obj) = split /\./, $key, 2;
		next unless defined $obj;

		# Climb to the nearest policy-map object above this class.
		my $policy = '';
		my $p = $parent->{$key};
		my $guard = 0;
		while (defined $p && $p ne '0' && $guard++ < 32) {
			my $pkey = "$pol.$p";
			last unless defined $type->{$pkey};
			if ($type->{$pkey} eq $TYPE_POLICYMAP) {
				$policy = $pm_name->{$config->{$pkey}} if defined $config->{$pkey};
				last;
			}
			$p = $parent->{$pkey};
		}

		my $ifi = $if_index->{$pol};
		my $interface;
		if (defined $if_type->{$pol} && $if_type->{$pol} eq $IFTYPE_CONTROL_PLANE) {
			$interface = 'control-plane';
		} elsif (defined $ifi && defined $names->{"$ifname_oid.$ifi"}) {
			$interface = $names->{"$ifname_oid.$ifi"};
		} else {
			$interface = 'ifIndex ' . (defined $ifi ? $ifi : '?');
		}

		push @rows, {
			index     => $key,
			pol       => $pol,
			obj       => $obj,
			class     => clean(defined $config->{$key} ? $cm_name->{$config->{$key}} : ''),
			policymap => clean($policy),
			interface => clean($interface),
		};
	}

	return sort { $a->{pol} <=> $b->{pol} || $a->{obj} <=> $b->{obj} } @rows;
}

sub get_counter {
	my $oid = shift;
	fail('missing index') unless $theindex =~ /^\d+\.\d+$/;
	my $r = get_many("$oid.$theindex");
	my $v = $r->{"$oid.$theindex"};
	return (defined $v && $v =~ /^\d+$/) ? $v : 'U';
}

if ($action1 eq 'index') {
	print "$_->{index}\n" foreach classes();
} elsif ($action1 eq 'num_indexes') {
	print scalar(my @c = classes()), "\n";
} elsif ($action1 eq 'query') {
	foreach my $c (classes()) {
		if ($action2 eq 'index') {
			print "$c->{index}!$c->{index}\n";
		} elsif ($action2 eq 'interface') {
			print "$c->{index}!$c->{interface}\n";
		} elsif ($action2 eq 'policymap') {
			print "$c->{index}!$c->{policymap}\n";
		} elsif ($action2 eq 'all') {
			print "Index:$c->{index} Policy:$c->{policymap} Class:$c->{class} Intf:$c->{interface}\n";
		} else {
			print "$c->{index}!$c->{class}\n";
		}
	}
} elsif ($action1 eq 'get' && $action2 eq 'bytes') {
	print get_counter($bytes_oid), "\n";
} elsif ($action1 eq 'get' && $action2 eq 'drops') {
	print get_counter($drops_oid), "\n";
} else {
	print $usage;
}

exit 0;
