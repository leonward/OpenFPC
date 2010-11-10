#!/usr/bin/perl -I ../

# leon@rm-rf.co.uk
# Quick script to test event parsing. Nothing to see here. Move on.


use strict;
use warnings;
use OpenFPC::Parse;
use Switch;

my $auto=0;

#############################################################
# Example event formats for testing the Parser
#############################################################
# SnortSyslog full details
#my $input="May  3 15:16:30 rancid snort: [1:13923:3] SMTP MailEnable SMTP HELO command denial of service attempt [Classification: Attempted Denial of     Service] [Priority: 2]: {TCP} 213.138.226.169:2690 -> 80.68.89.43:25"; # Snort syslog

# Exim4
#my $input="2010-04-05 10:23:12 1NyiWV-0002IK-QJ <= lodgersau3\@nattydreadtours.com H=(ABTS-AP-dynamic-117.149.169.122.airtelbroadband.in) [122.169.149.117] P=esmtp S=2056 id=000d01cad4a1\$ab5a3780\$6400a8c0\@lodgersau3"; # EXIM4

#Sourcefire 3D (copy/paste from IPS event table view)
#my $input="	 2010-03-31 13:24:36	 high	 	 	 IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	 tcp	Go to Host View 192.168.4.248	Go to Host View 207.46.108.86	 Viktor Westcott (viktor.westcott, ldap)	 	 3044/tcp	 1863/tcp	 Standard Text Rule	 CHAT MSN message (1:540)	 Potential Corporate Policy Violation	 0";   # SF49IPS 
#Sourcefire 3D 4.9.1
#my $input="2010-10-25 11:56:29	high		 	IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	tcp	 192.168.4.249	 69.104.33.82	 	 	3537/tcp	6667 (ircd)/tcp	Standard Text Rule	CHAT IRC message (1:1463)	Potential Corporate Policy Violation";
#my $input="	2010-10-26 21:54:27	high			IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	tcp	 10.4.12.53	 10.4.12.12	 	 Gabrielle Schmitt (gabrielle.schmitt, ldap)	32775/tcp	80 (http)/tcp	Standard Text Rule	WEB-IIS cmd.exe access (1:1002)	Web Application Attack	0";
my $input="2010-10-28 16:03:55	high		 	IPS Demo DE / sfukse3d00.lab.emea.sourcefire.com	tcp	 192.168.6.40	 195.54.102.4	 misterbear16 (aim)	 	3663/tcp	6668/tcp	Standard Text Rule	CHAT IRC message (1:1463)	Potential Corporate Policy Violation	0";

# Snort "Fast" format - full details
#my $input="05/14-09:01:49.390801  [**] [1:12628:2] RPC portmap Solaris sadmin port query udp portmapper sadmin port query attempt [**] [Classification: Decode of an RPC Query] [Priority: 2] {UDP} 192.168.133.50:666 -> 192.168.10.90:32772";

# Snort "Fast" format - missing port(s)
#my $input="05/14-09:01:49.390801  [**] [1:12628:2] RPC portmap Solaris sadmin port query udp portmapper sadmin port query attempt [**] [Classification: Decode of an RPC Query] [Priority: 2] {UDP} 192.168.133.50:12 -> 192.168.10.90:32772";
#my $input="05/14-09:01:49.390801  [**] [1:12628:2] RPC portmap Solaris sadmin port query udp portmapper sadmin port query attempt [**] [Classification: Decode of an RPC Query] [Priority: 2] {UDP} 192.168.133.50: -> 192.168.10.90:";

# Random ofpc-v1 samples
#my $input="ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 spt:3432 dpt:1234 proto:tcp time:246583 msg:Some freeform text";
#my $input="ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 dpt:22 proto:tcp time:1274864808 msg:Some freeform text";
#my $input="ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 dpt:22 spt:222 timestamp:1274864808";
#my $input="ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 dpt:22 spt:222 timestamp:1274864808";
#my $input="ofpc-v1 type:search dip:192.168.222.1 dpt:22 stime:1283171182 etime:1283174182";
#my $input="ofpc-v1 type:event sip:192.168.222.1 etime:1285142949";

# ofpc-v1-bpf BPF example
#my $input="ofpc-v1-bpf host 1.1.1.1 and host 2.2.2.2 not tcp port 23 stime:1274864808 etime:1274864899";

my %eventdata = ();


if ($auto) {
	print "* Autodetect type\n";
	while (1) {
		%eventdata=OpenFPC::Parse::ofpcv1BPF($input); if ($eventdata{'parsed'} ) { last; }
		%eventdata=OpenFPC::Parse::OFPC1Event($input); if ($eventdata{'parsed'} ) { last; }
		%eventdata=OpenFPC::Parse::SF49IPS($input); if ($eventdata{'parsed'} ) { last; }
		%eventdata=OpenFPC::Parse::Exim4($input); if ($eventdata{'parsed'} ) { last; }
		%eventdata=OpenFPC::Parse::SnortSyslog($input); if ($eventdata{'parsed'} ) { last; }
		%eventdata=OpenFPC::Parse::SnortFast($input); if ($eventdata{'parsed'} ) { last; }
		die("Unable to parse log. Doesn't match anything")
	}
} else { # Manual 
	print "* Manual type set\n";
		%eventdata=OpenFPC::Parse::SF49IPS($input); 
}
	if ($eventdata{'type'}) {
		print "\nGot event type $eventdata{'type'}\n";
		print "SIP = $eventdata{'sip'}  DIP = $eventdata{'dip'}\n" .
		"SPT = $eventdata{'spt'} DPT = $eventdata{'dpt'} \n" .
		"proto = $eventdata{'proto'} \n" .
		"msg = $eventdata{'msg'} \ntimestamp = $eventdata{'timestamp'} \n" .
		"bpf = $eventdata{'bpf'} \nparsed = $eventdata{'parsed'}\n" .
		"Device = $eventdata{'device'} \n" .
		"stime = $eventdata{'stime'} \n" .
		"etime = $eventdata{'etime'} \n" .

		"------------------------------\n";
	}

print "\n\n";

