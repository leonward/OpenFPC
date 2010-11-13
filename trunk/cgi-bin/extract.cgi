#!/usr/bin/perl
#########################################################################################
# Copyright (C) 2010 Leon Ward 
# extract.cgi - Part of the OpenFPC - (Full Packet Capture) project
#
# Contact: leon@openfpc.org
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

# This is a simple CGI interface to allow external tools to request data from OpenFPC's traffic
# buffer(s).

use warnings;
use strict;
use Date::Parse;
use OpenFPC::Request;
use OpenFPC::Parse;
use CGI ':standard';
use IO::Socket::INET;
use Data::Dumper;
use File::Temp(qw(tempdir));

# Enter your username and password for OpenFPC here
# TODO: Decide if these should be configured here, or in a .conf somewhere.
# For now, this works fine.

my $openfpcuser="openfpc";	# Username to log into the openfpc-queued instance
my $openfpcpass="openfpc";	# Password to log into the openfpc-queued instance
my $openfpcserver="localhost";	# OpenFPC Queue address (hostname/ip)
my $openfpcport="4242";		# OpenFPC port
############# Nothing to do below this line #################
my $debug=0;	# If 1, we will display data about the extracted file rather than
		# push the pcap file for download directly. Includes verbose data

my %req=(   	user => $openfpcuser,
                password => $openfpcpass,
                action => "fetch", 
                device => 0,
                logtype => 0,
                filetype => 0,
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
		filename => 0,
                );  
my %result=(
                success => 0,
                filename => 0,
                position => 0,
                md5 => 0,
                expected_md5 => 0,
                message => 0,
                size => 0,
		filetype => 0,
);  
my $tempdir=tempdir(CLEANUP => 1);
my $now=time();

=head2 norm_time
	Take a timestamp, and shell out to the date command to convert it into epoch
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

# Input validation of param(s);
if (defined param('sip')) { 
	$req{'sip'} = param('sip') 		if param('sip')  =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ ;
}
if (defined param('dip')) {
	$req{'dip'} = param('dip')      	if param('dip')	 =~ 	/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/; 
}
if (defined param('proto')) {
	$req{'proto'}	= param('proto')    	if param('proto')	 =~ 	/^(tcp|udp|icmp)$/;
}
if (defined param('dpt')) {
	$req{'dpt'}  	= param('dpt')      	if param('dpt')	 =~ 	/^\d{1,5}$/;
}
if (defined param('spt')) {
	$req{'spt'}  	= param('spt')      	if param('spt')	 =~ 	/^\d{1,5}$/;
}
if (defined param('action')) {
	$req{'action'}	= param('action')   	if param('action')    =~   /^(fetch|store|status)$/;
}
if (defined param('comment')) {
	$req{'comment'}	= param('comment')  	if param('comment')   =~   /^[A-Za-z0-9\s]/;
}
if (defined param('filename')) {
	$req{'filename'}= param('filename') 	if param('filename')  =~   /^[A-Za-z0-9\s]/;
}
if (defined param('logline')) {
	$req{'logline'}	= param('logline')  	if param('logline');      # How can I validate this? 
}
if (defined param('debug')){ 
	$debug=1 if param('debug');
}
if (defined param('timestamp')) {
	$req{'timestamp'} = norm_time(param('timestamp'));
}
if (defined param('stime')) {
	$req{'stime'} = norm_time(param('stime'));
}
if (defined param('etime')){
	$req{'etime'} = norm_time(param('etime'));
}

# Timestamps are "special" because we want to support multiple date formats. Date::Parse to the rescue!

unless ($req{'filename'}) {
	$req{'filename'} = "$tempdir/openfpc-noname-$now";
} else {
	$req{'filename'} = "$tempdir/$req{'filename'}";
}

unless ($req{'logline'}) {
	my $logline=OpenFPC::Parse::sessionToLogline(\%req);
        $req{'logline'} = $logline;
}

my $sock = IO::Socket::INET->new(
	PeerAddr => $openfpcserver,
	PeerPort => $openfpcport,
	Proto => 'tcp',
);
unless ($sock) {
	print "Content-type: text/html\n\n";
        $result{'message'} = "Unable to create socket to server $openfpcserver on TCP:$openfpcport\n";
	print "Error $result{'message'} \n"; 
}
 
%result=OpenFPC::Request::request($sock,\%req);
close($sock);

if ($debug) {
	print "Content-type: text/html\n\n";
	print "<pre>--------------------------------------------------\n".
		"OpenFPC - External extraction interface \n" .	
		"Leon Ward 2010 - www.openfpc.org \n" .
		"--------------------------------------------------\n" .
		"<pre>Debug Mode: Args being used for extraction script \n" .
		"sip = $req{'sip'} \n" .
		"dip = $req{'dip'} \n" .
		"spt = $req{'spt'} \n" .
		"dpt = $req{'dpt'} \n" .
		"protocol = $req{'proto'} \n" .
		"Logline = $req{'logline'} \n" .
		"Timestamp = $req{'timestamp'} (" . localtime($req{'timestamp'}) . ")\n" .
		"sTimestamp = $req{'stime'} (" . localtime($req{'stime'}) . ")\n".
		"eTimestamp = $req{'etime'} (" . localtime($req{'etime'}) . ")\n".
		"Filename = $req{'filename'}\n" .
		"now = $now (" . localtime($now) .") \n";

	print "-----------Result-----------\n" .
		"Message: $result{'message'} <br>" .
		"Filename: $result{'filename'}<br>". 
		"MD5 $result{'md5'}<br>" .
		"Success: $result{'success'} <br>" .
		"Size: $result{'size'} <br>" .
		"Filetype: $result{'filetype'} \n" .
		"\n" ;
	print Dumper %result;
} else {
	if ($result{'success'}) {

		if ($result{'filetype'} eq "PCAP") {
			print "Content-Type: application/pcap-capture\n";
			print "Content-Disposition:attachment;filename=$result{'filename'}\n\n";
		} elsif ($result{'filetype'} eq "ZIP") {
			print "Content-Type: application/zip\n";
			print "Content-Disposition:attachment;filename=$result{'filename'}\n\n";
		} else {
			print "Content-type: text/html\n\n";
			print "Error, invalid filetype $result{'filetype'}\n";
		}

		open (FILE,"$result{'filename'}") ;
		my @payload=<FILE>;
		print @payload;
		close (FILE);
	} else {
			print "Content-type: text/html\n\n";
			print "Error, Check server logs for more data $result{'message'}\n";

	}

}


#File::Temp::cleanup();
