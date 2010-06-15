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

# The start of an interactive setup script for openfpc

use strict;
use warnings;

# Confguration Defaults
my $debug=1;
my $filename="ofpc.conf";
my $confdir=".";
my (%userlist, %oldconfig, %config,%question,%validation);


# This is a hash of things we need to configure. It contains the variable, and the question to present to the user

$question{"ofpcuser"} = "User ID to run the ofpc process as";
$question{"mode"} = "Operation mode, (master/slave)";

$validation{'mode'} = "(master|slave)";

sub askq{
	# Ask a question, return an answer
	my $key=shift;

	while(1) { 	# Continue forever until we recieve valid input
		print "$question{$key}: ";
		my $response=<STDIN>;
		chomp $response;
		$response=lc($response);		# Keep all config in lower case
		$config{$key} = $response;

		if (defined $validation{$key}) {
			print "Input validation required for $key\n" if ($debug);
			if ($response =~ m/$validation{$key}/ ) {
				return($response);	
			} else {
				print "Invalid input \"$response\". Hit CRTL+C to break out \n";
			}
		} else {
			print "No validation performed on $key\n" if ($debug);
			return($response);
		}
	}
}

# ---------- Start here -----------
open(CONFIG, , "$confdir/$filename") or die("cant open pcap file $confdir/$filename");

while(<CONFIG>) {
        chomp;
        if ( $_ =~ m/^[a-zA-Z]/) {
                (my $key, my @value) = split /=/, $_; 
                unless ($key eq "USER") {
                        $config{$key} = join '=', @value;
                } else {
                        print "C- Adding user:$value[0]: Pass:$value[1]\n" if ($debug);
                        $userlist{$value[0]} = $value[1] ;
                }   
        }   
}
close CONFIG;

foreach my $key (keys %question) {
	$config{$key}=askq($key);
	print "Setting $key to $config{$key}\n" if ($debug);
}

