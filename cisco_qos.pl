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

#use warnings;

use strict;

my $node = $ARGV[0];
my $comm = $ARGV[1];
my $action1 = $ARGV[2];
my $action2 = $ARGV[3];
my $theindex = $ARGV[4];

my $snmppath = "/usr/bin/snmpwalk";
my $snmpget = "/usr/bin/snmpget";
my $version = "2c";
my $class_name_oid = ".1.3.6.1.4.1.9.9.166.1.7.1.1.1";  # lists the classes
my $policy_name_oid = ".1.3.6.1.4.1.9.9.166.1.6.1.1.1"; # lists the polices

my $ifIndex_oid = ".1.3.6.1.4.1.9.9.166.1.1.1.1.4"; #list of ifIndexes
my $ifName_oid = ".1.3.6.1.2.1.31.1.1.1.1";

my $config_index_oid = "1.3.6.1.4.1.9.9.166.1.5.1.1.2"; # lists the references
my $bytes_oid = "1.3.6.1.4.1.9.9.166.1.15.1.1.10";      # lists the pol/obj id refs
my $drops_oid = "1.3.6.1.4.1.9.9.166.1.15.1.1.16";


my @classes;
my @polices;
my @class_index;
my @ifNamearray;
my $ifName;
my $policy_index;
my $policy_name;
my $interface;
my $ifName;

sub indexes {
        my $dowhatever = shift;

        my @class_name = `$snmppath -v$version -c $comm $node $class_name_oid`;
        my @policy_names = `$snmppath -v$version -c $comm $node $policy_name_oid`;
        my @config_index = `$snmppath -v$version -c $comm $node $config_index_oid`;
        my @ifIndex = `$snmppath -v$version -c $comm $node $ifIndex_oid`;

        foreach (@class_name) {
                s/"//g ;
                my @littlearray = split / /;
                my @values = split /\./, $littlearray[0];

                push @classes, "$values[-1]:$littlearray[3]\n" ;
        }
        foreach (@policy_names) {
                s/"//g;
                my @littlearray = split / /;
                my @values = split /\./, $littlearray[0];

                push @polices, "$values[-1]:$littlearray[3]\n" ;
        }

        foreach (@config_index) {
                s/"//g ;
                my @littlearray = split / /;
                my @values = split /\./, $littlearray[0];
                chomp $littlearray[3];

                foreach (@polices) {
                        my ($policy_config, $policy) = split /:/;
                        chomp $policy;
                        chomp $policy_config;
                        if ($littlearray[3] eq $policy_config) {
                                $policy_index = $values[-2];
                                $policy_name = $policy;
                                foreach (@ifIndex) {
                                        s/"//g ;
                                        my @littlearray = split / /;
                                        my @oid = split /\./, $littlearray[0];
                                        chomp $littlearray[3];
                                        if ($oid[-1] eq $policy_index) {
                                                $ifName = `$snmpget -v$version -c $comm $node $ifName_oid.$littlearray[3]`;
                                                my @ifNamearray = split (/ /,$ifName);
                                                chomp $ifNamearray[3];
                                                $ifNamearray[3] =~ s/"//go;
                                                $interface = $ifNamearray[3];
                                        }
                                }
                        }
                }
                foreach (@classes) {
                        my ($class_config, $class) = split /:/;
                        chomp $class;
                        chomp $class_config;

                        if (($littlearray[3] eq $class_config) && ($values[-2] eq $policy_index)) {
                                chomp $class;
                                chomp $policy_name;
                                if ($dowhatever eq "query"){
                                        if($action2 eq 'index') {
                                                push @class_index , "$values[-2].$values[-1]!$values[-2].$values[-1]\n";
                                        } 
                                        elsif ($action2 eq 'interface') {
                                                push @class_index , "$values[-2].$values[-1]!$interface\n";
                                        }
                                        elsif ($action2 eq 'policymap') {
                                                push @class_index , "$values[-2].$values[-1]!$policy_name\n";
                                        }
                                        elsif ($action2 eq 'all') {
                                                push @class_index , "Index:$values[-2].$values[-1] Policy:$policy_name Class:$class Intf:$interface\n";
                                        }


                                        else {
                                                push @class_index , "$values[-2].$values[-1]!$class\n";
                                        }
                                }
                                elsif ($dowhatever eq "index"){
                                        push @class_index , "$values[-2].$values[-1]\n";
                                }
                        }
                }
        }
        return @class_index
}

sub get_drops {
        my $index_value = shift;
        my $drops = `$snmpget -v$version -c $comm $node $drops_oid.$index_value`;
        my @dropsarray = split (/ /,$drops);
        chomp $dropsarray[3];
        return $dropsarray[3];
}
sub get_bytes {
        my $index_value = shift;
        my $bytes = `$snmpget -v$version -c $comm $node $bytes_oid.$index_value`;
        my @bytesarray = split (/ /,$bytes);
        chomp $bytesarray[3];
        return $bytesarray[3];
}
ARGUMENTS: {
        if ($action1 eq "index") { print indexes("index") ; last ARGUMENTS; }
        if ($action1 eq "query") { print indexes("query") ; last ARGUMENTS; }
        if ($action2 eq "bytes") { print get_bytes("$theindex") ; last ARGUMENTS; }
        if ($action2 eq "drops") { print get_drops("$theindex") ; last ARGUMENTS; }


        print "usage:\n
               ./cisco_qos.pl IP COMMUNITY index
               ./cisco_qos.pl IP COMMUNITY query [index|policymap|interface|all]
               ./cisco_qos.pl IP COMMUNITY get {bytes|drops} index_oid\n";
}

exit;
