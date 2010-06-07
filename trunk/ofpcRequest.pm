package ofpcRequest;

#########################################################################################
# Copyright (C) 2009 Leon Ward 
# ofpcRequest - Part of the OpenFPC - (Full Packet Capture) project
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
use ofpcParse;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
require Exporter;
use Switch;
use Digest::MD5(qw(md5_hex));
@EXPORT = qw(ALL);
$VERSION = '0.01';

sub request{
	# Take a request hash, and a socket, do as asked and return success and a filename, or fail error
	my $socket=shift;
	my $request=shift;
	my $debug=1;
	my ($protover);
	if ($debug) {
		print Dumper $request;	
	}
	my $protover="OFPC-v1";
	
	my ($event,$result)=ofpcParse::parselog($request->{'logline'});
	unless ($event) {
		return (0,$result);
	}

	if ($event->{'sip'}) { $request->{'sip'} = $event->{'sip'} ;}
	if ($event->{'dip'}) { $request->{'dip'} = $event->{'dip'} ;}
	if ($event->{'dpt'}) { $request->{'dpt'} = $event->{'dpt'} ;}
	if ($event->{'spt'}) { $request->{'spt'} = $event->{'spt'} ;}
	if ($event->{'proto'}) { $request->{'proto'} = $event->{'proto'} ;}
	if ($event->{'timestamp'}) { $request->{'timestamp'} = $event->{'timestamp'} ;}
	if ($event->{'type'}) { $request->{'type'} = $event->{'type'} ;}
	if ($event->{'msg'}) { $request->{'msg'} = $event->{'msg'} ;}
	
	# Selecting buffer device related to event src isn't dont yet.
	print "WARNING: Device selection not done yet -> Using all\n" if ($debug);

	if ($debug) {
                print "   ---ofpcRequest---\n" .
                "   User        $request->{'user'}\n" .
                "   RID         $request->{'rid'}\n".
                "   Action:     $request->{'action'}\n" .
                "   Device:     $request->{'device'}\n" .
                "   Filename:   $request->{'filename'}\n" .
                "   Tempfile:   $request->{'tempfile'}\n" .
                "   Location:   $request->{'location'}\n" .
                "   Type:       $request->{'logtype'}\n" .
                "   LogLine:    $request->{'logline'}\n" .
                "   SIP:        $request->{'sip'}\n" .
                "   DIP:        $request->{'dip'}\n" .
                "   Proto:      $request->{'proto'}\n".
                "   SPT:        $request->{'spt'}\n" .
                "   DPT:        $request->{'dpt'}\n" .
                "   MSG:        $request->{'msg'}\n" .
                "   Timestamp   $request->{'timestamp'}\n" .
                "   StartTime   $request->{'stime'}\n" .
                "   EndTime     $request->{'etime'}\n" ;
        }   

	# It is expected that any request will have already been sanity checked, but we do it again incase

	# The following are required to make any type of request:
	unless ($request->{'user'}) { return(0,"No user specified"); }
	unless ($request->{'action'} =~ m/(queue|fetch)/) { return(0,"Invalid action $request->{'action'}"); }
	
	# Make request from Socket
	my $reqstring="$request->{'user'}||" .
			"$request->{'action'}||" .
			"$request->{'device'}||" .
			"$request->{'filename'}||" .
			"$request->{'location'}||" .
			"$request->{'logtype'}||" .
			"$request->{'logline'}";

	while(my $connection = $socket->connected) { # While we are connected to the server
        	my $data=<$socket>;
        	print "Waiting for Data\n" if ($debug);
            	chomp $data;
                print "DEBUG: GOT DATA: $data\n" if ($debug);

                switch($data) {
                        case /OFPC READY/ { 
                                print "DEBUG: Got banner: Sending my protover $protover\n" if ($debug);
                                print $socket "$protover\n";
                        }
                        case /OFPC-v1 OK/ { 
                                print "DEBUG: Sending User $request->{'user'}" if ($debug);
                                print $socket "USER: $request->{'user'}\n" ;
                        }   
                        case /CHALLENGE/ {
                                if ($data =~ /CHALLENGE:\s+(\d+)/) {
                                        my $challenge=$1;
                                        print "DEBUG: Got Challenge $1\n" if ($debug);
                                        my $response=md5_hex("$challenge$request->{'password'}");
                                        print "DEBUG: Sending Response : $response\n" if ($debug);
                                        print $socket "RESPONSE:$response\n";
                                } else {
                                        print "DEBUG: CHALLENGE ERROR\n" if ($debug);
                                        print $socket "ERROR\n";
                                }
                        } case /WAIT/ {
                                        if ($data =~ /^WAIT:*\s*(\d+)/) {
                                                my $position=$1;
                                                print "DEBUG: Request accepted. Queue position $position. Waiting.....\n";
                                        } else {
                                                print "DEBUG: Request accepted. Queue position problem Waiting.....\n";
                                        }
                        } case /PCAP/ {
                                        print "DEBUG: Incomming PCAP\n";
                                        my $md5;
                                        if ($data =~ /^PCAP:\s*(.*)/) {
                                                $md5=$1;
                                        }
                                        print "GOT MD5 $md5\n";

                                        open (PCAP,'>',"$request->{'filename'}");
                                        binmode(PCAP);
                                        binmode($socket);
                                        my $data;
                                        while (sysread($socket,$data,1024,0)){
                                                syswrite(PCAP, $data,1024,0);
                                        }
                                        close($socket);
                                        close(PCAP);
                                        open(PCAPMD5, '<', "$request->{'filename'}") or die("cant open pcap file $request->{'filename'}");
                                        my $xfermd5=Digest::MD5->new->addfile(*PCAPMD5)->hexdigest;
                                        close(PCAPMD5);
                                        print "Epxect: $md5\n Got   : $xfermd5\n";
     			} case /QUEUED/ {
                                        if ($data =~ /^QUEUE:*\s*(\d+)/) {
                                                my $position=$1;
                                                print "DEBUG: Request accepted. Queue postion $position. Disconnecting\n";
                                                shutdown($socket,2);
                                        } else {
                                                print "DEBUG: Request accepted. Queueposition unknown. Disconnection\n";
                                                shutdown($socket,2);
                                        }
                        } case /ERROR/ {
					if ($data =~ m/^ERROR:(.*)/) {
	                                        print "DEBUG: Got error: $1 :closing connection\n";
					}
                                        shutdown($socket,2);
                        } case /AUTH OK/ {
                                print "DEBUG: Password OK\n" if ($debug);
                                print $socket "REQ:$reqstring\n";
                                print "Data submitted\n";
                        }
                        case /AUTH FAIL/ {
                                print "DEBUG: Password BAD\n" if ($debug);
                                print "Bad password\n";
                        #} else {
                        #        die("Unknown server response $data") ;
                        }
                }
	}
	
	return(0,"Not complete");
}

1;
