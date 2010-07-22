#!/usr/bin/perl -I /home/lward/code/openfpc/

#########################################################################################
# Copyright (C) 2010 Leon Ward 
# client.pl - Part of the OpenFPC - (Full Packet Capture) project
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
use Data::Dumper;
use IO::Socket::INET;
use ofpc::Request; 
use ofpc::Parse;
use Getopt::Long;
use Switch;
use Digest::MD5(qw(md5_hex));

my $now=time();

# Hint: "ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 dpt:22 proto:tcp timestamp:1274864808 msg:Some freeform text";
my %cmdargs=( user => "ofpc",
	 	password => 0, 
		server => "localhost",
		port => "4242",
		action => "fetch",
		logtype => "auto",
		debug => 0,
		verbose => 0,
		filename => "/tmp/extracted-ofpc-$now.pcap",
		logline => 0,
		quiet => 0,
		gui => 0,
		);

my %request=(	user => 0,
		password => 0,
		action => 0,
		device => 0,
		logtype => 0,
		logline => 0,
		sip => 0,
		dip => 0,
		spt => 0,
		dpt => 0,
		proto => 0,
		timestamp => 0,
		stime => 0,
		etime => 0,
		comment => 0,
		);

my %result=(
		success => 0,
		filename => 0,
		position => 0,
		md5 => 0,
		expected_md5 => 0,
		message => 0,
		size => 0,
	);

sub showhelp{
	print <<EOF 
  ./ofpc-client.pl <options>

  --------   General   -------
  --server or -s <ofpc server IP>	ofpc server to connect to
  --port or -o <TCP PORT>		Port to connect to (default 4242)
  --user or -u <username>		Username	
  --password or -p <password>		Password (if not supplied, it will be prompted for)
  --action or -a <action>		OFPC action to take, e.g. fetch, store, status, status, ctx
  --verbose or -v 			Run in verbose mode
  --debug or -d				Run in debug mode (very verbose)
  --write or -w				Output PCAP file to write to
  --quiet or -q				Quiet, shhhhhhh please. Only print saved filename||error
  --gui	or -g				Output that's parseable via OpenFPC's gui (or other tool)
  --comment or -m 			Comment for session

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

sub sessionToLogline{
	# ofpc-v1 type:event sip:1.1.1.1 dip:1.1.1.1 spt:3432 dpt:1234 proto:tcp time:246583 msg:Some freeform text
	# Take in a hash of session data, and return a "ofpc-v1" log format

	my $req=shift;
	my $logline = "ofpc-v1 ";
	
	if ($req->{'stime'} or $req->{'etime'}) {
		$logline .= "type:search ";
	} else {
		$logline .= "type:event ";
	}
	$logline .= "sip:$req->{'sip'} " if ($req->{'sip'});
	$logline .= "dip:$req->{'dip'} " if ($req->{'dip'});
	$logline .= "dpt:$req->{'dpt'} " if ($req->{'dpt'});
	$logline .= "spt:$req->{'spt'} " if ($req->{'spt'});

	if ($req->{'timestamp'}) {
		#my $epoch=`date --date='$req->{'timestamp'}' +%s` or die "Cant make sense of timestamp $req->{'timestamp'}";
		$logline .= "timestamp:$req->{'timestamp'} ";
	}

	return($logline);
}

sub displayResult{

	if ($result{'success'} == 1) { 			# Request is Okay and being processed
		unless ($cmdargs{'gui'}) {  		# Command line output
			if ($request{'action'} eq "fetch") {
				print "$result{'filename'} size:$result{'size'}\n";
				print "$result{'md5'}\n";
			} else {
				print 	"Queue Position: $result{'position'} \n".
					"Remote File   : $result{'filename'}\n" .
					"Result        : $result{'message'}\n";
			}
		} else {			# GUI firendly output
						# Provide output that is easy to parse
						# result=0   	Fail
						# result=1	success
						# result,action,filename,size,md5,expected_md5,position,message
			print "1,$request{'action'},$result{'filename'},$result{'size'},$result{'md5'},$result{'expected_md5'}," .
				"$result{'position'},$result{'message'}\n";
		}
	} else {				# Problem with request, provide fail info
		if ($cmdargs{'gui'}) {
			print "0,$request{'action'},$result{'filename'},$result{'size'},$result{'md5'},$result{'expected_md5'}," .
				"$result{'position'},$result{'message'}\n";
		} else {
			print "Problem processing request: $result{'message'}\n";
			print "Expected: $result{'expected_md5'}\n" if ($result{'expected_md5'});
			print "Got     : $result{'md5'}\n" if ($result{'md5'});
		}
	}
}


my (%config,$verbose,$debug);
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
		'e|logline=s' => \$cmdargs{'logline'},
		'a|action=s' => \$cmdargs{'action'},
		'p|password=s' => \$cmdargs{'password'},
		'm|comment=s' => \$cmdargs{'comment'},
		'g|gui'	=> \$cmdargs{'gui'},
		't|time|timestamp=s' => \$cmdargs{'timestamp'},
		'src-addr=s' => \$cmdargs{'sip'},
                'dst-addr=s' => \$cmdargs{'dip'}, 
                'src-port=s' => \$cmdargs{'spt'},
                'dst-port=s' => \$cmdargs{'dpt'},
                'proto=s' => \$cmdargs{'proto'},
                );

if ($cmdargs{'user'}) { $request{'user'} = $cmdargs{'user'}; }
if ($cmdargs{'server'}) { $config{'server'} = $cmdargs{'server'}; }
if ($cmdargs{'port'}) { $config{'port'} = $cmdargs{'port'}; }
if ($cmdargs{'filename'}) { $request{'filename'} = $cmdargs{'filename'}; }
if ($cmdargs{'logtype'}) { $request{'logtype'} = $cmdargs{'logtype'}; }
if ($cmdargs{'action'}) { $request{'action'} = $cmdargs{'action'}; }
if ($cmdargs{'logline'}) { $request{'logline'} = $cmdargs{'logline'}; }
if ($cmdargs{'password'}) { $request{'password'} = $cmdargs{'password'}; }
if ($cmdargs{'comment'}) { $request{'comment'} = $cmdargs{'comment'}; }

if ($cmdargs{'debug'}) { 
	$debug=1;
	$verbose=1;
}

if ($debug) {
	print "----Config----\n".
	"Server:		$config{'server'}\n" .
	"Port:		$config{'port'}\n" .
	"User: 		$request{'user'}\n" .
	"Action:	$request{'action'}\n" .
	"Logtype:	$request{'logtype'}\n" .
	"Logline:	$request{'logline'}\n" .
	"Filename:	$cmdargs{'filename'}\n" .
	"\n";
}

# Provide a banner and queue position if were not in GUI or quiet mode
unless( ($cmdargs{'quiet'} or $cmdargs{'gui'})) {
	print "\n   * ofpc-client.pl $version * \n   Part of the OpenFPC project\n\n" ;
	$request{'showposition'} = 1;
}

if ($cmdargs{'help'}) {
	showhelp;
	exit;
}

# Check we have enough constraints to make an extraction with.
if ($request{'action'} =~ m/(fetch|store)/)  {
	unless ($request{'logline'} or ($cmdargs{'sip'} or $cmdargs{'dip'} or $cmdargs{'spt'} or $cmdargs{'dpt'} )) {
		showhelp;
		print "Error: This action requres a request line or session identifiers\n\n";
		exit;
	}
} else {
	die("Action $request{'action'} invalid, or not implemented yet");
}

# If we are in GUI mode, PHP's escapecmd function could have broken out logline, lets unescape it

if ($cmdargs{'gui'}) {
	$request{'logline'} =~ s/\\(.)/$1/g;
}


# Convert session info into a "logline" to make a request.
unless ($cmdargs{'logline'}) {
	my $logline=sessionToLogline(\%cmdargs);
	$request{'logline'} = $logline;	
}

my $sock = IO::Socket::INET->new(
				PeerAddr => $config{'server'},
                                PeerPort => $config{'port'},
                                Proto => 'tcp',
                                );  
unless ($sock) { 
	$result{'message'} = "Unable to create socket to server $config{'server'} on TCP:$config{'port'}\n"; 
	displayResult($cmdargs{'gui'});
	exit 1;
}

unless ($request{'password'}) {
	print "Password for user $request{'user'} : ";
	my $userpass=<STDIN>;
	chomp $userpass;
	$request{'password'} = $userpass;
}

%result=ofpc::Request::request($sock,\%request);
close($sock);

displayResult($cmdargs{'gui'});

# provide output back to the user / gui
