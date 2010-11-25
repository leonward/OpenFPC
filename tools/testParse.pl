#!/usr/bin/perl -I ../

# leon@rm-rf.co.uk
# Quick script to test event parsing. Nothing to see here. Move on.


use strict;
use warnings;
use OpenFPC::Parse;
use Switch;
use Getopt::Long;
use Data::Dumper;


my $problem=0;
my $verbose=0;
my $oneline=0;
my $manual=0;
my $quiet=0;

my %logs=(
	SnortSyslog => [ 
			"May  3 15:16:30 rancid snort: [1:13923:3] SMTP MailEnable SMTP HELO command denial of service attempt [Classification: Attempted Denial of     Service] [Priority: 2]: {TCP} 213.138.226.169:2690 -> 80.68.89.43:25"
			] ,

	SF49IPS => 	[ 	
			"2010-03-31 13:24:36	 high	 	 	 IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	 tcp	Go to Host View 192.168.4.248	Go to Host View 207.46.108.86	 Viktor Westcott (viktor.westcott, ldap)	 	 3044/tcp	 1863/tcp	 Standard Text Rule	 CHAT MSN message (1:540)	 Potential Corporate Policy Violation	 0" ,
			"2010-10-25 11:56:29	high		 	IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	tcp	 192.168.4.249	 69.104.33.82	 	 	3537/tcp	6667 (ircd)/tcp	Standard Text Rule	CHAT IRC message (1:1463)	Potential Corporate Policy Violation" ,
			"	2010-10-26 21:54:27	high			IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	tcp	 10.4.12.53	 10.4.12.12	 	 Gabrielle Schmitt (gabrielle.schmitt, ldap)	32775/tcp	80 (http)/tcp	Standard Text Rule	WEB-IIS cmd.exe access (1:1002)	Web Application Attack	0" ,
			"2010-10-28 16:03:55	high		 	IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	tcp	 192.168.6.40	 195.54.102.4	 misterbear16 (aim)	 	3663/tcp	6668/tcp	Standard Text Rule	CHAT IRC message (1:1463)	Potential Corporate Policy Violation	0" 
			] ,

	Exim4 => 	[ 	
			"2010-04-05 10:23:12 1NyiWV-0002IK-QJ <= lodgersau3\@nattydreadtours.com H=(ABTS-AP-dynamic-117.149.169.122.airtelbroadband.in) [122.169.149.117] P=esmtp S=2056 id=000d01cad4a1\$ab5a3780\$6400a8c0\@lodgersau3" 
			],

	SnortFast => 	[ 	
			"05/14-09:01:49.390801  [**] [1:12628:2] RPC portmap Solaris sadmin port query udp portmapper sadmin port query attempt [**] [Classification: Decode of an RPC Query] [Priority: 2] {UDP} 192.168.133.50:666 -> 192.168.10.90:32772" ,
			"05/14-09:01:49.390801  [**] [1:12628:2] RPC portmap Solaris sadmin port query udp portmapper sadmin port query attempt [**] [Classification: Decode of an RPC Query] [Priority: 2] {UDP} 192.168.133.50:12 -> 192.168.10.90:32772" ,
			"05/14-09:01:49.390801  [**] [1:12628:2] RPC portmap Solaris sadmin port query udp portmapper sadmin port query attempt [**] [Classification: Decode of an RPC Query] [Priority: 2] {UDP} 192.168.133.50: -> 192.168.10.90:" ,
			"1/24-10-10:43:38.846134  [**] [1:2000:0] Snort Alert [1:2000:0] [**] [Priority: 0] {TCP} 10.10.0.26:38941 -> 10.7.255.53:22" 
			] ,

	OFPC1Event => 	[ 
			"ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 spt:3432 dpt:1234 proto:tcp timestamp:246583 msg:Some freeform text" ,
			"ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 dpt:22 proto:tcp timestamp:1274864808 msg:Some freeform text" ,
			"ofpc-v1 type:event sip:192.168.222.1 timestamp:1285142949" 
			] ,

	ofpcv1BPF => 	[ 
			"ofpc-v1-bpf bpf: host 1.1.1.1 and host 2.2.2.2 not tcp port 23 stime:1274864808 etime:1274864899" 
			] ,
);

sub checkParse{
	my $logline=shift;
	my %eventdata=();
	my %tmpdata=(
                'type' => "UnSet",
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

	while (1) {
		%tmpdata=OpenFPC::Parse::ofpcv1BPF($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OpenFPC::Parse::OFPC1Event($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OpenFPC::Parse::SF49IPS($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OpenFPC::Parse::Exim4($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OpenFPC::Parse::SnortSyslog($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OpenFPC::Parse::SnortFast($logline); if ($tmpdata{'parsed'} ) { last; }
		last;
	}
	
	if ($tmpdata{'parsed'}) {
		%eventdata=%tmpdata;
		print "[*] Event Parsed as $eventdata{'type'}\n" unless ($quiet);
		return(\%eventdata);
	} else {
		$problem = $logline;
		print "[*] ERROR Cant parse event!\n";
		print "    $logline\n";
		print "------------------------------\n";
		return(\%tmpdata);
	}
}

sub displayEvent{
	my $eventdata=shift;
	#print Dumper $eventdata;
	print "    SIP = $eventdata->{'sip'}  DIP = $eventdata->{'dip'}\n" .
		"    SPT = $eventdata->{'spt'} DPT = $eventdata->{'dpt'} \n" .
		"    proto = $eventdata->{'proto'} \n" .
		"    msg = $eventdata->{'msg'} \n" .
		"    timestamp = $eventdata->{'timestamp'} (" . localtime($eventdata->{'timestamp'}) . ") \n" .
		"    BPF = $eventdata->{'bpf'} \n" .
		"    Parsed = $eventdata->{'parsed'}\n" .
		"    Device = $eventdata->{'device'} \n" .
		"    Start time = $eventdata->{'stime'} \n" .
		"    End time = $eventdata->{'etime'} \n" .
		"------------------------------\n";
}

GetOptions (    'o|oneline' => \$oneline,
		'm|manual' => \$manual,
		'v|verbose' => \$verbose,
		'q|quiet' => \$quiet,
	);

unless ($oneline) {
	print "* Autodetect type\n" unless ($quiet);
	foreach my $type (keys(%logs)) {		# For every log type
		foreach(@{$logs{$type}}) {		# For each log line of that type
			print "[-] Event type $type\n" unless $quiet;
			print " V  $_\n" if ($verbose);
			my $result=checkParse($_);
			unless ($quiet) {
				displayEvent($result) if ($result->{'parsed'});
			}
		}
	}
} 

if ($oneline)  {
	print "Enter Logline\n";
	my $logline=<STDIN>;
	chomp $logline;

	unless ($manual) {
		my $result=checkParse($logline); 
		displayEvent($result);
	} else {
		print "[*] Manual Tests...\n";
		my %tmpdata=OpenFPC::Parse::SnortFast($logline);
		displayEvent(\%tmpdata);
	}
}

if ($problem) {
	print "ERROR, problem found with one or more logs !\n";
	exit 1;
}
