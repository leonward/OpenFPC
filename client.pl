#!/usr/bin/perl -I .

use strict;
use warnings;
use IO::Socket::INET;
use ofpc::Request; 
use ofpc::Parse;
use Getopt::Long;
use Switch;
use Digest::MD5(qw(md5_hex));

# Hint: "ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 dpt:22 proto:tcp time:1274864808 msg:Some freeform text";

sub showhelp{
	print <<EOF 
  ./ofpc-client.pl <options>

  --------   General   -------
  --server or -s <ofpc server IP>	ofpc server to connect to
  --port or -o <TCP PORT>		Port to connect to (default 4242)
  --user or -u <username>		Username	
  --password or -p <password>		Password (if not supplied, it will be prompted for)
  --action or -a  <action>		OFPC action to take, e.g. fetch, store, status, status, ctx
  --verbose or -v 			Run in verbose mode
  --debug or -d				Run in debug mode (very verbose)
  --write or -w				Output PCAP file to write to
  --quiet or -q				Quiet, shhhhhhh please. Only print saved filename||error

  -------- Constraints -------

  --logline or -e <line>		Logline, must be supported by ofpc::Parse
  --src-addr <host>			Source IP
  --dst-addr <host>			Destination IP
  --src-port <port>			Source Port
  --dst-port <port>			Destination Port
  --vlan <vlan>				VLAN ID (NOT DONE YET)
  --timestamp	<timestamp>		Event timestamp
  --eachway <count>			Numer of files to search over  (NOT DONE YET)

EOF
}

my %cmdargs=( user => "ofpc",
	 	password => 0, 
		server => "localhost",
		port => "4242",
		action => "fetch",
		logtype => "auto",
		debug => 0,
		verbose => 0,
		filename => "/tmp/foo.pcap",
		logline => 0,
		quiet => 0,
		);

my (%request, %config,$verbose,$debug);
my $version=0.1;

GetOptions (    'u|user=s' => \$cmdargs{'user'},
		's|server=s' => \$cmdargs{'server'},
		'o|port=s' => \$cmdargs{'port'},
		'd|debug' => \$cmdargs{'debug'},
		'h|help' => \$cmdargs{'help'},
		'q|quiet' => \$cmdargs{'quiet'},
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
	"Filename:	$cmdargs{'filename'}\n" .
	"\n";
}

print "\n   * ofpc-client.pl $version * \n   Part of the OpenFPC project\n\n" unless($cmdargs{'quiet'});
# Check we have what we need for a connection, if not show help

if ($cmdargs{'help'}) {
	showhelp;
	exit;
}

if ($request{'action'} =~ m/(fetch|store)/)  {
	unless ($request{'logline'}) {
		showhelp;
		print "Error: This action requres a request line or session identifiers\n\n";
		exit;
	}
}

my $sock = IO::Socket::INET->new(
				PeerAddr => $config{'server'},
                                PeerPort => $config{'port'},
                                Proto => 'tcp',
                                );  
unless ($sock) { die("Unable to create socket to server $config{'server'} on TCTP:$config{'port'}"); }

unless ($request{'password'}) {
	print "Password for user $request{'user'} : ";
	my $userpass=<STDIN>;
	chomp $userpass;
	$request{'password'} = $userpass;
}

my ($result, $message)=ofpc::Request::request($sock,\%request);
if ($result == 1) {
	if ($request{'action'} eq "fetch") {
		# As we have the file locally, lets provide some metadata
		my $filesize=`ls -lh $request{'filename'} |awk '{print \$5}'`;
		chomp $filesize;
		print "$request{'filename'} Saved, $filesize\n";
	} else {
		print "Result: $message\n";
	}
} else {
	print "Problem processing request : $message\n";
}
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
