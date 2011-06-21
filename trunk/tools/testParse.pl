#!/usr/bin/perl -I ../

# leon@rm-rf.co.uk
# Quick script to test event parsing. Nothing to see here. Move on.


use strict;
use warnings;
use OFPC::Parse;
use Switch;
use Getopt::Long;
use Data::Dumper;


my $problem=0;
my $verbose=0;
my $oneline=0;
my $manual=0;
my $quiet=0;
my $help;

my %logs=(
	SnortSyslog => [ 
			"May  3 15:16:30 rancid snort: [1:13923:3] SMTP MailEnable SMTP HELO command denial of service attempt [Classification: Attempted Denial of     Service] [Priority: 2]: {TCP} 213.138.226.169:2690 -> 80.68.89.43:25",
			"Dec  2 13:02:49 zorro snort[25811]: [138:4:1] SENSITIVE-DATA U.S. Social Security Numbers w/out dashes [Classification: Senstive Data] [Priority: 2] {TCP} 192.168.42.107:60521 -> 209.85.229.102:80" ,
			"Dec  2 13:03:18 zorro snort[25811]: [138:5:1] SENSITIVE-DATA Email Addresses [Classification: Senstive Data] [Priority: 2] {TCP} 192.168.42.107:60521 -> 209.85.229.102:80",
			"Dec  8 11:14:03 zorro snort[20352]: [139:1:1] SDF_COMBO_ALERT [Classification: Senstive Data] [Priority: 2] {PROTO:254} 90.25.16.110 -> 192.168.2.10"
			] ,

	SF49IPS => 	[ 	
			"2010-03-31 13:24:36	 high	 	 	 IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	 tcp	Go to Host View 192.168.4.248	Go to Host View 207.46.108.86	 Viktor Westcott (viktor.westcott, ldap)	 	 3044/tcp	 1863/tcp	 Standard Text Rule	 CHAT MSN message (1:540)	 Potential Corporate Policy Violation	 0" ,
			"2010-10-25 11:56:29	high		 	IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	tcp	 192.168.4.249	 69.104.33.82	 	 	3537/tcp	6667 (ircd)/tcp	Standard Text Rule	CHAT IRC message (1:1463)	Potential Corporate Policy Violation" ,
			"	2010-10-26 21:54:27	high			IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	tcp	 10.4.12.53	 10.4.12.12	 	 Gabrielle Schmitt (gabrielle.schmitt, ldap)	32775/tcp	80 (http)/tcp	Standard Text Rule	WEB-IIS cmd.exe access (1:1002)	Web Application Attack	0" ,
			"2010-10-28 16:03:55	high		 	IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	tcp	 192.168.6.40	 195.54.102.4	 misterbear16 (aim)	 	3663/tcp	6668/tcp	Standard Text Rule	CHAT IRC message (1:1463)	Potential Corporate Policy Violation	0",
			"	2011-06-21 19:47:17	high		 	Demo IPS / sfukse3d01.lab.emea.sourcefire.com	tcp	 192.168.6.60	 66.225.225.225	 sourab.gita (POP3)	 	49180/tcp	6667 (ircd)/tcp	Standard Text Rule	CHAT IRC channel join (1:1729)	Potential Corporate Policy Violation	0"
			] ,

	Exim4 => 	[ 	
			"2010-04-05 10:23:12 1NyiWV-0002IK-QJ <= lodgersau3\@nattydreadtours.com H=(ABTS-AP-dynamic-117.149.169.122.airtelbroadband.in) [122.169.149.117] P=esmtp S=2056 id=000d01cad4a1\$ab5a3780\$6400a8c0\@lodgersau3" 
			],

	SnortFast => 	[ 	
			"05/14-09:01:49.390801  [**] [1:12628:2] RPC portmap Solaris sadmin port query udp portmapper sadmin port query attempt [**] [Classification: Decode of an RPC Query] [Priority: 2] {UDP} 192.168.133.50:666 -> 192.168.10.90:32772" ,
			"05/14-09:01:49.390801  [**] [1:12628:2] RPC portmap Solaris sadmin port query udp portmapper sadmin port query attempt [**] [Classification: Decode of an RPC Query] [Priority: 2] {UDP} 192.168.133.50:12 -> 192.168.10.90:32772" ,
			"05/14-09:01:49.390801  [**] [1:12628:2] RPC portmap Solaris sadmin port query udp portmapper sadmin port query attempt [**] [Classification: Decode of an RPC Query] [Priority: 2] {UDP} 192.168.133.50: -> 192.168.10.90:" ,
			"1/24-10-10:43:38.846134  [**] [1:2000:0] Snort Alert [1:2000:0] [**] [Priority: 0] {TCP} 10.0.0.2:3941 -> 10.10.20.53:80",
		        "11/30/10-16:07:28.998446  [**] [1:2000:0] Snort Alert [1:2000:0] [**] [Priority: 0] {TCP} 10.0.0.1:3722 -> 10.10.20.53:22",
			] ,

	OFPC1Event => 	[ 
			"ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 spt:3432 dpt:1234 proto:tcp timestamp:246583 msg:Some freeform text" ,
			"ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 dpt:22 proto:tcp timestamp:1274864808 msg:Some freeform text" ,
			"ofpc-v1 type:event sip:192.168.222.1 timestamp:1285142949" 
			] ,

	ofpcv1BPF => 	[ 
			"ofpc-v1-bpf bpf: host 1.1.1.1 and host 2.2.2.2 not tcp port 23 stime:1274864808 etime:1274864899" 
			] ,
	pradslog => 	[
			"192.168.42.5,0,22,6,SERVER,[ssh:OpenSSH 5.3p1 (Protocol 2.0)],0,1290888581",
			"192.168.42.107,0,443,6,CLIENT,[unknown:\@https],0,1290816603",
			"173.194.36.83,0,443,6,SERVER,[unknown:\@https],10,1290816603",
			],
	nftracker => 	[
			"1291893772,6,85.19.221.54,42696,217.147.81.2,80,exe",
			"1292119164,6,217.69.134.176,51630,85.19.221.54,80,pdf",
			"1292142613,6,85.19.221.54,59406,78.46.89.231,80,png" ,
			"1292144009,6,85.19.221.54,34695,78.46.89.231,80,png" 
			],
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
		%tmpdata=OFPC::Parse::ofpcv1BPF($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OFPC::Parse::OFPC1Event($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OFPC::Parse::SF49IPS($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OFPC::Parse::Exim4($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OFPC::Parse::SnortSyslog($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OFPC::Parse::SnortFast($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OFPC::Parse::pradslog($logline); if ($tmpdata{'parsed'} ) { last; }
		%tmpdata=OFPC::Parse::nftracker($logline); if ($tmpdata{'parsed'} ) { last; }
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

sub showhelp{
	print "testParse.pl - Test event text parsers
	
	Usage:
		-o or --oneline    Paste your event into an interactive prompt
		-m or --manual	   Only parse with the hard-coded parser
		-q or --quiet	   Only output if there is an error
		-h or --help	   This message\n\n";
}

GetOptions (    'o|oneline' => \$oneline,
		'm|manual' => \$manual,
		'v|verbose' => \$verbose,
		'q|quiet' => \$quiet,
		'h|help' => \$help,
	);

if ($help) {
	showhelp;
	exit(0);
}

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
		my %tmpdata=OFPC::Parse::SnortSyslog($logline);
		displayEvent(\%tmpdata);
	}
}

if ($problem) {
	print "ERROR, problem found with one or more logs !\n";
	exit 1;
}
