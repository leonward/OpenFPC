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
	my %event=(
		'type' => "SFIPS",
		'spt' => 0,
		'dpt' => 0,
		'sip' => 0,
		'dip' => 0,
		'proto' => 0,
		'msg' => "Sourcefire IPS event",
		'timestamp' => 0,
		'bpf' => 0,
		'parsed' =>0
		);

	my $logline=shift;

        if ($logline =~ m/(.*)( high| medium| low)/) {   # Timestamp comes before priority
        	$event{'timestamp'}=`date --date='$1' +%s`;
		chomp $event{'timestamp'};
        }   

        if ($logline =~ m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(.*)(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {   
                $event{'sip'}=$3;
                $event{'dip'}=$1;
        }   

	if ($logline =~ m/(\d{1,5})\/(tcp|udp)\s*(\d{1,5})\/(tcp|udp)/) {
                $event{'spt'}=$1;
                $event{'dpt'}=$3;
        }   

	if ($logline =~ m/(tcp|udp|icmp)\s*Go to Host View/ ) {
		$event{'proto'}=$1;
	}

	if ( $event{'sip'} and $event{'dip'} and $event{'timestamp'} and $event{'proto'} ) {
		$event{'parsed'} = 1;
	}

	return(%event);
}

sub Exim4{
	# Exim4 mainlog - As found on my Debian SMTP relay
	my %event=(
		'type' => "Exim4",
		'spt' => 0,
		'dpt' => 25,
		'sip' => 0,
		'dip' => 0,
		'proto' => "TCP",
		'msg' => "Email transfer",
		'timestamp' => 0,
		'bpf' => 0,
		'parsed' => 0
		);

	my $logline=shift;

	# Sample 2010-04-05 10:23:12 1NyiWV-0002IK-QJ <= lodgersau3@nattydreadtours.com H=(ABTS-AP-dynamic-117.149.169.122.airtelbroadband.in) [122.169.149.117] P=esmtp S=2056 id=000d01cad4a1$ab5a3780$6400a8c0@lodgersau3

	if ($logline =~ m/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/) {
		$event{'timestamp'}=`date --date='$1' +%s`;
		chomp $event{'timestamp'};
	}

	# Get direction of email, inbound is <= outbound is =>

	my $mailinbound=0;
	if ($logline =~ m/<=/) {
		$mailinbound=1;
	} 

	my $eventip;
	if ($logline =~ m/\[(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\]/) {
		if ($mailinbound) {
			$event{'sip'}=$1;
		} else {
			$event{'dip'}=$1;
		}
		$eventip=$1;
	}
	
	$event{'bpf'}="tcp host $eventip and tcp port 25";

	# Check we have enough to rtn a good event
	
	if ( ($event{'sip'} or $event{'dip'}) and $event{'timestamp'} and $event{'bpf'} ) {
		$event{'parsed'} = 1 ;
	}

	return(%event);
}

sub SnortSyslog{
	# Snort's syslog output: 
	my %event=(
		'type' => "SnortSyslog",
		'spt' => 0,
		'dpt' => 0,
		'sip' => 0,
		'dip' => 0,
		'proto' => 0,
		'msg' => "Snort IPS event",
		'timestamp' => 0,
		'bpf' => 0,
		'parsed' => 0
		);

	#Apr 11 14:03:45 rancid snort: [1:13923:3] SMTP MailEnable SMTP HELO command denial of service attempt [Classification: Attempted Denial of Service] [Priority: 2]: {TCP} 122.166.99.139:2135 -> 80.68.89.43:25
	# Apr 11 08:53:16 rancid snort: [1:254:7] DNS SPOOF query response with TTL of 1 min. and no authority [Classification: Potentially Bad Traffic] [Priority: 2]: {UDP} 80.68.80.24:53 -> 80.68.89.43:50331 	
# May  3 15:16:30 rancid snort: [1:13923:3] SMTP MailEnable SMTP HELO command denial of service attempt [Classification: Attempted Denial of Service] [Priority: 2]: {TCP} 213.138.226.169:2690 -> 80.68.89.43:25

	my $logline=shift;

	if ($logline =~ m/(\[[0-9]+:[0-9]+:[0-9]+] )(.*)(\[\*\*\])/) {
                $event{'msg'} = "Snort event: $2"; 
        }


	if ($logline =~ m/{(ICMP|TCP|UDP)}/) {
                $event{'proto'} = $1; 
        }

	if ($logline =~ m/(^.*\s\d\d:\d\d:\d\d\s)/) {
		$event{'timestamp'}=`date --date='$1' +%s`;
        	chomp $event{'timestamp'};
	} 

	
  	if ($event{'proto'} eq "ICMP") {
                if ($logline =~ m/(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b) -> (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/) {
                        $event{'sip'} = $1;
                        $event{'dip'} = $2;
               }
        } elsif (($event{'proto'} eq "TCP") | ($event{'proto'} eq "UDP")) {
                if ($logline =~ /((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):(\d+)) -> ((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):(\d+))/) {
                        $event{'sip'} = $2;
                        $event{'dip'} = $5;
                        $event{'spt'} = $3;
                        $event{'dpt'} = $6;
                }
	}

	 if ( ($event{'sip'} or $event{'dip'}) and $event{'proto'} and $event{'timestamp'} ) {
		$event{'parsed'}=1;
	}
	
	return(%event);

}


sub SnortFast{
	# Snort's alert-Fast output: 
	my %event=(
		'type' => "SnortFast",
		'spt' => 0,
		'dpt' => 0,
		'sip' => 0,
		'dip' => 0,
		'proto' => 0,
		'msg' => "Snort IPS event",
		'timestamp' => 0,
		'bpf' => 0,
		'parsed' => 0
		);

	#05/14-09:01:49.390801  [**] [1:12628:2] RPC portmap Solaris sadmin port query udp portmapper sadmin port query attempt [**] [Classification: Decode of an RPC Query] [Priority: 2] {UDP} 192.168.133.50:666 -> 192.168.10.90:32772

	my $logline=shift;

	if ($logline =~ m/(\[[0-9]+:[0-9]+:[0-9]+] )(.*)(\[\*\*\])/) {
                $event{'msg'} = "Snort event: $2"; 
        }

	if ($logline =~ m/{(ICMP|TCP|UDP)}/) {
                $event{'proto'} = $1; 
        }

	if ($logline =~ m/(^\s*\d\d\/\d\d-\d\d:\d\d:\d\d)/ ) { 
		my $tempdate=$1;
		$tempdate =~ s/-/ /g;
		$event{'timestamp'}=`date --date='$tempdate' +%s`;
        	chomp $event{'timestamp'};
	} 

	
  	if ($event{'proto'} eq "ICMP") {
                if ($logline =~ m/(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b) -> (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/) {
                        $event{'sip'} = $1;
                        $event{'dip'} = $2;
               }
        } elsif (($event{'proto'} eq "TCP") | ($event{'proto'} eq "UDP")) {
                if ($logline =~ /((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):(\d+)) -> ((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):(\d+))/) {
                        $event{'sip'} = $2;
                        $event{'dip'} = $5;
                        $event{'spt'} = $3;
                        $event{'dpt'} = $6;
                }
	}

	if ( ($event{'sip'} or $event{'dip'}) and $event{'proto'} and $event{'timestamp'} ) {
		$event{'parsed'}=1;
	}
	
	return(%event);

}



1;
