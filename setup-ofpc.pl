#!/usr/bin/perl -I .
#########################################################################################
# Copyright (C) 2010 Leon Ward 
# ofpc-setup.pl - Part of the OpenFPC - (Full Packet Capture) project
#
# Contact: leon@rm-rf.co.uk
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#########################################################################################

use strict;
use warnings;
use Getopt::Long;
use Data::Dumper;
use File::Copy;

# Confguration Defaults
my $debug=1;
my $file="./myopenfpc.conf";
my @configfiles=("/etc/ofpc.conf", "./etc/ofpc.conf");
my (%userlist, %oldconfig, %question,%validation,%cmdargs);

# Some system defaults. If there isn't a config files to read for current values, lets give the user a 
# hint to take something sensible.

my %config=( 
                OFPCUSER => "root",  
                saveconfig => "./myofpc.conf",  
                );  


# This is a hash of things we need to configure. It contains the variable, and the question to present to the user
$question{"OFPCUSER"} = "What User ID would you like to run the ofpc process as?";
$question{"MODE"} = "Select operation mode:\n Master: Central queue manager\n Slave: Performs capture and extraction if data.\n (master/slave)";

# Input validations to make sure we get valid data as part of the setup questions.
# Format is a key, and then a pcre to m/$stuff/.
$validation{'MODE'} = "(master|slave)";

sub askq{
	# Ask a question, return an answer
	# I expect the variable I am to populate, and an optional default value.
	# e.g. askq("user","root");
	# I return the value the user has input, e.g root

	my $key=shift;
	my $default=shift;

	while(1) { 	# Continue forever until we receive valid input
		print "$question{$key} ($default): ";
		my $response=<STDIN>;
		chomp $response;
		if ($response) {
			$response=lc($response);		# Keep all config in lower case
			#$config{$key} = $response;
		} else {   # No input, take default value
			$response=$default;
		}

		if (defined $validation{$key}) {
			print "Input validation check found for $key" if ($debug);
			if ($response =~ m/$validation{$key}/ ) {
				print "-> Passed\n" if ($debug);
				return($response);	
			} else {
				print "-> failed\n" if ($debug);
				print "Invalid input \"$response\". Hit CRTL+C to break out \n";
			}
		} else {
			print "No validation performed on $key\n" if ($debug);
			return($response);
		}
	}
}

# ---------- Start here -----------

GetOptions (    'c|config=s' => \$cmdargs{'file'},);

if (defined $cmdargs{'file'}) {
	$file=$cmdargs{'file'};
} else {
	# Look for a file in the obvious locations
	foreach(@configfiles) {
		if ( -f $_)  {
			print "Look $_\n";
			$file=$_;
			last;
		}
	} 
}

if (-f $file) {
	open(CONFIG,'<', "$file") or die("cant open pcap file $file");
	while(<CONFIG>) {
        	chomp;
	        if ( $_ =~ m/^[a-zA-Z]/) {
	                (my $key, my @value) = split /=/, $_; 
        	        unless ($key eq "USER") {
                	        $config{$key} = join '=', @value;
                	} else {
                        	$userlist{$value[0]} = $value[1] ;
                	}   
        	}   
	}
	close CONFIG;
}

print "* Working on config file $file\n" if ($debug);

print Dumper %config if ($debug);

foreach my $key (keys %question) {
	# If there is a value already set in the config file, provide it as
	# a default value (press enter to keep it).
	if (defined $config{$key}) {
		$config{$key}=askq($key,$config{$key});
	} else {
		$config{$key}=askq($key,"");
	}
	print "Setting $key to $config{$key}\n" if ($debug);
}

open(NEWCONFIG,'>', "$config{'saveconfig'}") or die("cant open file $config{'saveconfig'}");
print "#OpenFPC config \n";
foreach (keys %config) {
	print "$_=$config{$_}\n";
}
close($config{'saveconfig'});

