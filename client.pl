#!/usr/bin/perl -I .

use strict;
use warnings;
use IO::Socket::INET;
use ofpcRequest; 
use ofpcParse;
use Getopt::Long;
use Switch;
use Digest::MD5(qw(md5_hex));

# "ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 dpt:22 proto:tcp time:1274864808 msg:Some freeform text";

my %cmdargs=( user => 0,
	 	password => 0, 
		server => "localhost",
		port => "4242",
		action => "fetch",
		logtype => "auto",
		debug => 1,
		verbose => 0,
		filename => "/tmp/foo.pcap",
		logline => 0,
		);
my (%request, %config,$debug,$verbose);
$debug=1;
GetOptions (    'u|user=s' => \$cmdargs{'user'},
		's|server=s' => \$cmdargs{'server'},
		'o|port=s' => \$cmdargs{'port'},
		'd|debug' => \$cmdargs{'debug'},
		'w|write=s'=> \$cmdargs{'filename'},
		'v|verbose' => \$cmdargs{'verbose'},
		't|logtype=s' => \$cmdargs{'logtype'},
		'l|event=s' => \$cmdargs{'logline'},
		'a|action=s' => \$cmdargs{'action'},
		'p|password=s' => \$cmdargs{'password'},
                );

# Set some default values

if ($cmdargs{'user'}) { $request{'user'} = $cmdargs{'user'}; }
if ($cmdargs{'server'}) { $config{'server'} = $cmdargs{'server'}; }
if ($cmdargs{'port'}) { $config{'port'} = $cmdargs{'port'}; }
if ($cmdargs{'filename'}) { $request{'filename'} = $cmdargs{'filename'}; }
if ($cmdargs{'logtype'}) { $request{'logtype'} = $cmdargs{'logtype'}; }
if ($cmdargs{'action'}) { $request{'action'} = $cmdargs{'action'}; }
if ($cmdargs{'logline'}) { $request{'logline'} = $cmdargs{'logline'}; }
if ($cmdargs{'password'}) { $request{'password'} = $cmdargs{'password'}; }

if ($cmdargs{'debug'}) { 
	$debug=1;
	$verbose=1;
}

if ($debug) {
	print "----Config----\n".
	"Server:		$config{'server'}\n" .
	"Port:		$config{'port'}\n" .
	"User: 		$request{'user'}\n" .
	"Action:		$request{'action'}\n" .
	"Logtype:	$request{'logtype'}\n" .
	"Logline:	$request{'logline'}\n" .
	"Filename:	$config{'filename'}\n" .
	"\n";
}


my $sock = IO::Socket::INET->new(
				PeerAddr => $config{'server'},
                                PeerPort => $config{'port'},
                                Proto => 'tcp',
                                );  
unless ($sock) { die("Problem creating socket!"); }

unless ($request{'password'}) {
	print "Password: ";
	my $userpass=<STDIN>;
	chomp $userpass;
	$request{'password'} = $userpass;
}

my ($result, $message)=ofpcRequest::request($sock,\%request);

print "Result is $result\n";
print "Message is $message\n";
close($sock);
	#my $file="/tmp/bar.txt";
	#open(FILE,'>', "$file") or die ("unable to open file for write");
	#binmode(FILE);
	#my $data;
	#while (sysread($sock,$data, 1024,0)) {
#		syswrite(FILE, $data,1024,0);
#		print ".";
	#}
	#print "Done\n";
	#close(FILE);
	#close($sock);
