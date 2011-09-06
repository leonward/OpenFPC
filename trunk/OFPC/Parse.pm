package OFPC::Parse;

#########################################################################################
# Copyright (C) 2009 Leon Ward 
# OFPC::Parse - Part of the OpenFPC - (Full Packet Capture) project
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
use Date::Parse;

@EXPORT = qw(ALL);
$VERSION = '0.2';

=head2 sessionToLogline

	Take a hashref of session id's (sip,dip,timestamp etc) and return a "logline" that
	can be made in an ofpc-vX request.

	# Examples of output:
	# ofpc-v1 type:event sip:1.1.1.1 dip:1.1.1.1 spt:3432 dpt:1234 proto:tcp time:246583 msg:Some freeform text
	# ofpc-v1-bpf type:search bpf: host 1.1.1.1 and not tcp port 22 stime: 12345 etime: 43213
	- Leon
=cut

sub sessionToLogline{
	# Take in a hash of session data, and return a "ofpc" log format

	my $timeoffset=600;
	my $now=time();
	my $req=shift;
	my $logline;

	if ($req->{'bpf'}) {
		$logline = "ofpc-v1-bpf ";
	} else {
		$logline = "ofpc-v1 ";
	}

	# Event  = single timestamp -> Give me packets from around this timetstamp
	# Search = Start/End time   -> Look for traffic between these two timestamps

	if ($req->{'stime'} or $req->{'etime'}) {
		$logline .= "type:search ";
	} else {
		$logline .= "type:event ";
	}

	if ($req->{'bpf'}) {
		$logline .= "bpf: $req->{'bpf'} ";
	} else {
		$logline .= "sip:$req->{'sip'} " if ($req->{'sip'});
		$logline .= "dip:$req->{'dip'} " if ($req->{'dip'});
		$logline .= "dpt:$req->{'dpt'} " if ($req->{'dpt'});
		$logline .= "spt:$req->{'spt'} " if ($req->{'spt'});
		$logline .= "proto:$req->{'proto'} " if ($req->{'proto'});
	}	

	$logline .= "stime:$req->{'stime'} " if ($req->{'stime'});
	$logline .= "etime:$req->{'etime'} " if ($req->{'etime'});
	$logline .= "timestamp:$req->{'timestamp'} " if ($req->{'timestamp'});

	unless ($req->{'timestamp'}) {
		# No timestamp specified, lets assume a NOW - $timeoffset seconds
		$req->{'timestamp'} = $now - $timeoffset unless (($req->{'stime'} and $req->{'etime'})) ;	
		$logline .= "timestamp:$req->{'timestamp'} ";
	}

	return($logline);
}


=head2 norm_time
        Take a timestamp, and convert it into epoch.
	This is basically a wrapper for str2time function provided by Date::Time with
	an ability to catch values that are already epoch.
=cut

sub norm_time($) {
        # Pass me some time format, and ill give you an epoch value
        my $ts=shift;
        my $epoch;

        unless ( $ts =~ /^\d{1,10}$/ ) { 
                $epoch=str2time($ts);
                return($epoch);
        } else {
                return($ts);
        }   
}

sub parselog{
        # Recieve a logline, and return a ref to a hash that contains its data if valid
        my $logline=shift;
	my $debug=0;
        if ($debug) { print "   Parsing the logline :$logline\n"; }
        my %eventdata = ();     # Hash of decoded event

        # Work through a list of file-parsers until we get a hit        
        while (1) {
                %eventdata=OFPC::Parse::OFPC1Event($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=OFPC::Parse::SF49IPS($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=OFPC::Parse::Exim4($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=OFPC::Parse::SnortSyslog($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=OFPC::Parse::SnortFast($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=OFPC::Parse::ofpcv1BPF($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=OFPC::Parse::pradslog($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=OFPC::Parse::nftracker($logline); if ($eventdata{'parsed'} ) { last; }
                return(0, "Unable to parse log message");
        }   
 
        if ($debug) {
                print "   ---Decoded Event from parselog---\n" .
                       "   Type: $eventdata{'type'}\n" .
                       "   Timestamp: $eventdata{'timestamp'} (" . localtime($eventdata{'timestamp'}) . ")\n" .
		       "   stime: $eventdata{'stime'} \n" .
		       "   etime: $eventdata{'etime'} \n" .
                       "   SIP: $eventdata{'sip'}\n" .
                       "   DIP: $eventdata{'dip'}\n" .
                       "   SPT: $eventdata{'spt'}\n" .
                       "   DPT: $eventdata{'dpt'}\n" .
		       "   Device: $eventdata{'dev'}\n" .
                       "   Protocol: $eventdata{'proto'}\n" .
                       "   Message: $eventdata{'msg'}\n" ;
        }   

        return(\%eventdata,"Success");
}

####################################################
# Input = logfile line
# Output = hash of..
# Type,Timestamp,SrcIP, DstIP, SrcPort, DstPort, Proto, comment/msg


sub OFPC1Event{
	# OFPC-v1 Client request (text or GUI)

	my %event=(
		'type' => "OFPC Generic",
		'spt' => 0,
		'dpt' => 0,
		'sip' => 0,
		'dip' => 0,
		'proto' => 0,
		'msg' => "User request",
		'timestamp' => 0,
		'bpf' => 0,
		'device' => 0,
		'stime' => 0,
		'etime' => 0,
		'parsed' => 0
		);

	# ofpc-v1 type:event sip:1.1.1.1 dip:1.1.1.1 spt:3432 dpt:1234 proto:tcp timestamp:246583 msg:Some freeform text
	my $logline=shift;

	if ($logline =~ m/msg:(.*)/) {
                $event{'msg'} = "OFPC User request: $1"; 
        }

	if ($logline =~ m/proto:(tcp|udp|icmp)\s/i) {
                $event{'proto'} = $1; 
        }

	if ($logline =~ m/proto:(6|1|17)\s/i) {
		# Convert protocol number into its text name
		if ($1 == 17){
                	$event{'proto'} = "udp"; 
		} elsif ($1 == 1) {
                	$event{'proto'} = "icmp"; 
		} elsif ($1 == 6) {
                	$event{'proto'} = "tcp"; 
		} else {
                	$event{'proto'} = $1; 
		}
        }
	
	
	if ($logline =~ m/timestamp:\s*(\d{1,20})/) { 
		#m/timestamp:\s*(\d*)\s/ ) { 
        	$event{'timestamp'}=$1;
	} 
	
	if ($logline =~ m/stime:\s*(\d{1,20})/) { 
		#m/timestamp:\s*(\d*)\s/ ) { 
        	$event{'stime'}=$1;
	} 
	
	if ($logline =~ m/etime:\s*(\d{1,20})/) { 
		#m/timestamp:\s*(\d*)\s/ ) { 
        	$event{'etime'}=$1;
	} 

	
        if ($logline =~ /sip:\s*(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/) {
                        $event{'sip'} = $1;
	}
        if ($logline =~ /dip:\s*(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/) {
                        $event{'dip'} = $1;
	}

        if ($logline =~ /spt:\s*(\d{1,5})/) {
                        $event{'spt'} = $1;
	}
        if ($logline =~ /dpt:\s*(\d{1,5})/) {
                        $event{'dpt'} = $1;
	}
	# ofpc-v1 Events start with ofpc-v1 type:event
	# here
	if ( ($logline =~/^ofpc-v1\s*type:\s*event/i) and ($event{'timestamp'})) {
		$event{'parsed'}=1;
	}
	
	if ( ($logline =~/^ofpc-v1\s*type:\s*search/i) and ($event{'stime'} and $event{'etime'})) {
		$event{'parsed'}=1;
	}

	print Dumper %event;
	return(%event);

}


sub SF49IPS{
	# Sourcefire 3D 4.9 IPS event
	# Example event:
	# 2010-03-31 13:24:36     high                    IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com        tcp    Go to Host View 192.168.4.248   Go to Host View 207.46.108.86    Viktor     Westcott (viktor.westcott, ldap)                 3044/tcp        1863/tcp        Standard Text Rule      CHAT MSN message (1:540)        Potential Corporate Policy Violation    0


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
		'device' => 0,
		'parsed' => 0,
		'stime' => 0,
		'etime' => 0
		);

	my $logline=shift;
        if ($logline =~ m/(.*)( *high| medium| low)/) {   # Timestamp comes before priority
		$event{'timestamp'}=norm_time($1);
        }   
	if ($logline =~ m/( high| medium| low)\s+(.*) \//) {
		$event{'device'} = $2;
	}

        if ($logline =~ m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(.*)(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {   
                $event{'sip'}=$3;
                $event{'dip'}=$1;
        }   

	if  ($logline =~ m/(\d{1,5})(\/tcp|\/udp|.*{2-10}\/tcp|.*{2-10}\/udp).(\d{1,5})( |\/)/) {
                $event{'spt'}=$1;
                $event{'dpt'}=$3;
        }   

	if ($logline =~ m/(tcp|udp|icmp)/ ) {
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
		'device' => 0,
		'parsed' => 0,
		'stime' => 0,
		'etime' => 0,
		);

	my $logline=shift;

	# Sample 2010-04-05 10:23:12 1NyiWV-0002IK-QJ <= lodgersau3@nattydreadtours.com H=(ABTS-AP-dynamic-117.149.169.122.airtelbroadband.in) [122.169.149.117] P=esmtp S=2056 id=000d01cad4a1$ab5a3780$6400a8c0@lodgersau3

	if ($logline =~ m/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/) {
		$event{'timestamp'}=norm_time($1);
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
		'device' => 0,
		'stime' => 0,
		'etime' => 0,
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
		$event{'timestamp'}=norm_time($1);	
	} 

	if ($logline =~ m/([a-zA-Z]+ )snort:/ ) {
		$event{'device'} = $1;
	}

        if (($event{'proto'} eq "TCP") | ($event{'proto'} eq "UDP")) {
                if ($logline =~ /((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):(\d+)) -> ((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):(\d+))/) {
                        $event{'sip'} = $2;
                        $event{'dip'} = $5;
                        $event{'spt'} = $3;
                        $event{'dpt'} = $6;
                }
	} else {
                if ($logline =~ m/(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b) -> (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/) {
                        $event{'sip'} = $1;
                        $event{'dip'} = $2;
               }
	}

	if ( ($event{'sip'} or $event{'dip'}) and $event{'timestamp'} ) {
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
		'device' => 0,
		'parsed' => 0,
		'stime' => 0,
		'etime' => 0,
		);

	#05/14-09:01:49.390801  [**] [1:12628:2] RPC portmap Solaris sadmin port query udp portmapper sadmin port query attempt [**] [Classification: Decode of an RPC Query] [Priority: 2] {UDP} 192.168.133.50:666 -> 192.168.10.90:32772

	my $logline=shift;

	if ($logline =~ m/(\[[0-9]+:[0-9]+:[0-9]+] )(.*)(\[\*\*\])/) {
                $event{'msg'} = "Snort event: $2"; 
        }

	if ($logline =~ m/{(ICMP|TCP|UDP)}/) {
                $event{'proto'} = $1; 
        }

	if ($logline =~ m/^\s*(\d\d\/\d\d-\d\d:\d\d:\d\d)/ ) { 
		my $tempdate=$1;
		$tempdate =~ s/-/ /g;
		my $val=norm_time($tempdate);
		$event{'timestamp'} = $val;
	} 

	if ($logline =~ m/^\s*(\d+\/\d+-\d\d-\d\d:\d\d)/ ) { 
		my $tempdate=$1;
		# I have been shown two different format timestamps from
		# Barnyard, both are different from the Snort Fast output.
		# This is #1
		# Barnyard "fast" output uses - as a delimiter between month/year. This is a PITA
		# e.g. 1/24-10-10:43. A little split magic lets me break out date from time.
		my @foo=split(/-/, $tempdate);
		my $bar="$foo[0]/20$foo[1] $foo[2]$foo[3]";
		my $val=norm_time($bar);
		$event{'timestamp'} = $val;
	} 

	if ($logline =~ m/^\s*(\d+\/\d+\/\d+-\d+:\d+)/ ) { 
		my $tempdate=$1;

		# This is the second timestamp format I have been shown to 
		# come from Barnyard. It's also not standard to str2time 
		# cant parse it. It also has \d\d years!!!!

		my @datetime=split(/-/, $tempdate);
		my @mdy=split(/\//, $datetime[0]);
		my $str_to_convert=$mdy[0] . "/" . $mdy[1] . "/" . "20$mdy[2]" . " $datetime[1]";
		my $val=norm_time($str_to_convert);
		$event{'timestamp'} = $val;
	} 
	
  	if ($event{'proto'} eq "ICMP") {
                if ($logline =~ m/(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b) -> (\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/) {
                        $event{'sip'} = $1;
                        $event{'dip'} = $2;
               }
        } elsif (($event{'proto'} eq "TCP") | ($event{'proto'} eq "UDP")) {
                if ($logline =~ /((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):(\d*)) -> ((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):(\d*))/) {
                        $event{'sip'} = $2;
                        $event{'dip'} = $5;
                }

		# Grab a spt if there is one (user may want to remove it to grab more data)
                if ($logline =~ /((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):(\d+)) *->/) {
                        $event{'spt'} = $3;
		}

		# Grab a dpt if there is one (user may want to remove it to grab more data)
                if ($logline =~ /-> *((\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b):(\d+))/) {
                        $event{'dpt'} = $3;
		}
		# Here
		
	}

	if ( ($event{'sip'} or $event{'dip'}) and $event{'proto'} and $event{'timestamp'} ) {
		$event{'parsed'}=1;
	}
	
	return(%event);

}

=head2 initevent
	Init all of the values needed for a clean OpenFPC event parse
	simply do a %event=initevent();
	Takes 0 args, return a clean %event

	-Leon
=cut

sub initevent(){
	my %event=(
		'type' => 0,
		'spt' => 0,
		'dpt' => 0,
		'sip' => 0,
		'dip' => 0,
		'proto' => 0,
		'msg' => 0,
		'timestamp' => 0,
		'bpf' => 0,
		'device' => 0,
		'parsed' => 0,
		'stime' => 0,
		'etime' => 0,
		);

	return(%event);
}
=head2 pradsfile
	Parse a prads event (from log file) to pull out the session that created the
	assed discovery. -Leon
=cut

sub pradslog{
	my $logline=shift;
	my %event=initevent();
	$event{'type'} = "PradsLog";
	my $debug=0;

	$logline =~ s/@//;
	
	# The Prads log file is a csv file.
	# asset,vlan,port,proto,service,[service-info],distance,discovered
	# 192.168.42.5,0,22,6,SERVER,[ssh:OpenSSH 5.3p1 (Protocol 2.0)],0,1290888581

	if ((my $ip,	
		my $vlan,
		$event{'dpt'},
		my $ipproto,
		my $clisvr,	# CLIENT or SERVER
		$event{'msg'},
		my $hops,
		$event{'timestamp'} ) = split(/,/, $logline)) { 

		print "Got a good split\n" if ($debug);

		if ($clisvr eq "CLIENT") {
			$event{'sip'} = $ip;
		} else {
			$event{'dip'} = $ip;
		}	

		if ($ipproto == 6 ) {
			$event{'proto'} = "tcp";
		} else {
			$event{'proto'} = "udp";
		}

		if ($event{'timestamp'} and $event{'dpt'} )  {
			$event{'parsed'} = 1;
		}

	} else {
		print "Failed to decode prads event\n" if ($debug);
	}


	
	return(%event);
}

=head2 nftracker
	nftracker finds files as they move over the network.
 	# Example logs
	# timestamp,proto,src_ip,src_port,dst_ip,dst_port,FILE_TYPE
	# 1291893772,6,85.19.221.54,42696,217.147.81.2,80,exe
	# 1292119164,6,217.69.134.176,51630,85.19.221.54,80,pdf
=cut
sub nftracker{
	my $logline=shift;
	my %event=initevent();
	$event{'type'} = "nftracker log";
	my $debug=0;

	($event{'timestamp'},
		my $proto,
		$event{'sip'},
		$event{'spt'},
		$event{'dip'},
		$event{'dpt'},
		my $filetype) = split (/,/, $logline); 

	if ($event{'sip'} and $event{'dip'} and $event{'spt'} and $event{'dpt'} ) {
		$event{'msg'} = "Found filetype: $filetype";
		$event{'parsed'} = 1;
	}

	return(%event);
}

sub ofpcv1BPF{

	# User defined BPF
	my %event=(
		'type' => "ofpc-v1-bpf",
		'spt' => 0,
		'dpt' => 0,
		'sip' => 0,
		'dip' => 0,
		'proto' => 0,
		'msg' => 0,
		'timestamp' => 0,
		'bpf' => 0,
		'device' => 0,
		'parsed' => 0,
		'stime' => 0,
		'etime' => 0,
		);

	#BPF: host 1.1.1.1 and tcp port 22 timestamp:12345

	my $logline=shift;

	if ($logline =~ m/^(ofpc-v1-bpf)\s+.*bpf:\s+(.*?)(timestamp|stime|etime)/i) {
                $event{'msg'} = "User requested BPF: $logline"; 
		$event{'bpf'} = $2;
        }

	if ($logline =~ m/timestamp:\s*(\d{1,20})/) { 
        	$event{'timestamp'}=$1;
	} 
	
	if ($logline =~ m/stime:\s*(\d{1,20})/) { 
        	$event{'stime'}=$1;
	} 
	
	if ($logline =~ m/etime:\s*(\d{1,20})/) { 
        	$event{'etime'}=$1;
	} 

	if (( $event{'bpf'} and $event{'timestamp'}) or ( $event{'bpf'} and ($event{'stime'} and $event{'etime'}))) {
		$event{'parsed'}=1;
	}
	
	return(%event);
}

1;
