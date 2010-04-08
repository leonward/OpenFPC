package ofpcParse;

#########################################################################################
# Copyright (C) 2009 Leon Ward 
# ofpc-extract.pl - Part of the OpenFPC - (Full Packet Capture) project
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
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
require Exporter;

@EXPORT = qw(ALL);
$VERSION = '0.01';

####################################################
# Input = logfile line
# Output = array of..
# Type,Timestamp,SrcIP, DstIP, SrcPort, DstPort, Proto, comment/msg

sub SF49IPS{
	# Sourcefire 3D 4.9 IPS event

	my $event=shift;
	my $spt=0;
	my $dpt=0;
	my $sip=0;
	my $dip=0;
	my $proto=0;
	my $msg="Sourcefire IPS Event";
	my $epoch=0;

        if ($event =~ m/(.*)( high| medium| low)/) {   # Timestamp comes before priority
        	$epoch=`date --date='$1' +%s`;
		chomp $epoch;
        }   

        if ($event =~ m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(.*)(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {   
                $sip=$3;
                $dip=$1;
        }   

	if ($event =~ m/(\d{1,5})\/(tcp|udp)\s*(\d{1,5})\/(tcp|udp)/) {
                $spt=$1;
                $dpt=$3;
        }   

	if ($event =~ m/(tcp|udp|icmp)\s*Go to Host View/ ) {
		$proto=$1;
	}

	my @event=("SF49IPS",
			"$epoch" ,
			"$sip" ,
			"$dip" ,
			"$spt" , 
			"$dpt" ,
			"$proto" ,
			"$msg");
	return(@event);
}

sub EXIM4{
	# Exim4 mainlog - As found on my Debian SMTP relay
	my $event=shift;
	my $spt=0;
	my $dpt=0;
	my $sip=0;
	my $dip=0;	
	my $proto=0;
	my $epoch=0;
	my $msg="Email Transfer";
	# Sample 2010-04-05 10:23:12 1NyiWV-0002IK-QJ <= lodgersau3@nattydreadtours.com H=(ABTS-AP-dynamic-117.149.169.122.airtelbroadband.in) [122.169.149.117] P=esmtp S=2056 id=000d01cad4a1$ab5a3780$6400a8c0@lodgersau3

	if ($event =~ m/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/) {
		$epoch=`date --date='$1' +%s`;
		print "Date is $1 epoch = $epoch\n";
	}

	if ($event =~ m/\[(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\]/) {
		$sip=$1;
		print "SIP is $sip\n";
	}
}

sub SnortSyslog{
	# Sample: 
	my $event=shift;
	my $spt=0;
        my $dpt=0;
        my $sip=0;
        my $dip=0;    
        my $proto=0;
        my $epoch=0;
        my $msg="Email Transfer";

}

1;
