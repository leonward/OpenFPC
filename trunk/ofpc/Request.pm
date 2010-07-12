package ofpc::Request;

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
use ofpc::Parse;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
require Exporter;
use Switch;
use Digest::MD5(qw(md5_hex));
@EXPORT = qw(ALL);
$VERSION = '0.01';

sub request{
	# Take a request hash, and a socket, do as asked and return 
	# a hash of the result

	my $socket=shift;
	my $request=shift;
	my %result=(
			'success' => 0,
			'message' => 'none',
			'md5'	=> 0,
			'expected_md5'	=> 0,
			'filename' => 0,
			'size' => 0,
		);					# This is the hash we provide back to the calling function.
	my $debug=1;
	my $event=0;
	my ($protover);
	print Dumper $request if ($debug);
	my $protover="OFPC-v1";		# For future use.

	if ($request->{'logline'}) {
		($event, my $err)=ofpc::Parse::parselog($request->{'logline'});
		unless ($event) {
			$result{'success'} = 0;
			unless ($err) {
				$result{'message'} = "Failed local request validation. Not passing this request to server";
			} else {
				$result{'message'} = $err;
			}
			# Return a fail message
			return %result;
		}

		if ($event->{'sip'}) { $request->{'sip'} = $event->{'sip'} ;}
		if ($event->{'dip'}) { $request->{'dip'} = $event->{'dip'} ;}
		if ($event->{'dpt'}) { $request->{'dpt'} = $event->{'dpt'} ;}
		if ($event->{'spt'}) { $request->{'spt'} = $event->{'spt'} ;}
		if ($event->{'proto'}) { $request->{'proto'} = $event->{'proto'} ;}
		if ($event->{'timestamp'}) { $request->{'timestamp'} = $event->{'timestamp'} ;}
		if ($event->{'type'}) { $request->{'type'} = $event->{'type'} ;}
		if ($event->{'msg'}) { $request->{'msg'} = $event->{'msg'} ;}
	}	

	# Selecting buffer device related to event src isn't dont yet.
	print "WARNING: Device selection not done yet -> Using all\n" if ($debug);

	if ($debug) {
                print "   ---ofpcRequest---\n" .
                "   User        $request->{'user'}\n" .
                "   Password    $request->{'password'}\n" .
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
                "   EndTime     $request->{'etime'}\n" .
		"   ShowPos	$request->{'showposition'}" .
		"\n";
        }   

	# It is expected that any request will have already been sanity checked, but we do it again incase
	# The following are required to make any type of request:
	unless ($request->{'user'}) { 
		$result{'success'} = 0;
		$result{'message'} = "No user specified";
		return %result; 
	}
	unless ($request->{'action'} =~ m/(store|fetch|status)/) { 
		$result{'success'} = 0;
		$result{'message'} = "Invalid action $request->{'action'}";
	}
	
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
                                print "DEBUG: Got banner: $data: Sending my protover $protover\n" if ($debug);
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
                                        print $socket "ERROR Problem with challenge\n";
                                }
                        } case /WAIT/ {
                                        if ($data =~ /^WAIT:*\s*(\d+)/) {
						$result{'position'} = $1;
                                                #my $position=$1;
						if ( $request->{'showposition'} ){
							print "Queue position $result{'position'}. Wait...\n";
						}
						print "DEBUG: Position: $result{'position'}\n" if ($debug);
                                        } else {
                                                print "DEBUG: Request accepted. Queue position $result{'position'}  Waiting.....\n" if ($debug);
                                        }
                        } case /PCAP/ {
                                        print "DEBUG: Incomming PCAP\n" if ($debug);
                                        if ($data =~ /^PCAP:\s*(.*)/) {
						$result{'expected_md5'} = $1;
                                        }
                                        print "Expecting MD5 $result{'expected_md5'}\n" if ($debug);

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
				        $result{'size'}=`ls -lh $request->{'filename'} |awk '{print \$5}'`;
					chomp $result{'size'};
					print "DEBUG $request->{'filename'} size:$result{'size'}\n" if ($debug);
                                        # XXX
					#my $xfermd5=Digest::MD5->new->addfile(*PCAPMD5)->hexdigest;
					$result{'md5'}=Digest::MD5->new->addfile(*PCAPMD5)->hexdigest;
                                        close(PCAPMD5);
					print "$request->{'filename'} on disk is has md5 $result{'md5'}\n" if ($debug);
                                        print "Expected: $result{'expected_md5'}\nGot   : $result{'md5'}\n" if ($debug);
					if ($result{'md5'} eq $result{'expected_md5'}) {
						$result{'success'} = 1;
						$result{'filename'} = $request->{'filename'};
					} else {
						$result{'success'} = 0;
						$result{'filename'} = $request->{'filename'};
						$result{'error'} = "MD5 sum mismatch";
					}
					shutdown($socket,2);
					return %result;
			} case /FILENAME/ {
					if ($data =~ /^FILENAME:\s*(.*)/) {
						$result{'filename'} = $1;
						print "DEBUG: Got Filename: $result{'filename'}\n" if ($debug);
					}
     			} case /QUEUED/ {
                                        if ($data =~ /^QUEUED:*\s*(\d+)/) {
						# XXX	
                                                #my $position=$1;
						$result{'position'} = $1;
                                                print "DEBUG: Request accepted. Queue postion $result{'position'}. Disconnecting\n" if ($debug);
                                                shutdown($socket,2);
						$result{'message'} = "In Queue";
						$result{'success'} = 1;
						return %result;
                                        } else {
                                                print "DEBUG: Request accepted. Queue position unknown. Disconnecting\n" if ($debug);
						#return(1,"Request Queued. Position: unknown");
						$result{'success'} = 1;
						$result{'postion'} = "unknown";
                                                shutdown($socket,2);
						return %result;
                                        }
                        } case /ERROR/ {
					my $error;
					if ($data =~ m/^ERROR:(.*)/) {
						$result{'message'} = $1;
	                                        print "DEBUG: Got error: $result{'message'} :closing connection\n" if ($debug);
					}
                                        shutdown($socket,2);
					return %result;
                        } case /AUTH OK/ {
                                print "DEBUG: Password OK\n" if ($debug);
                                print $socket "REQ:$reqstring\n";
                                print "- Data submitted\n" if ($debug);
                        }
                        case /AUTH FAIL/ {
                                print "DEBUG: Password BAD\n" if ($debug);
				$result{'success'} = 0;
				$result{'message'} = "Authentication Failed";
                        #} else {
                        #        die("Unknown server response $data") ;
                        }
                }
	}

	$result{'message'} = "Something has gone wrong. You should never see this message - Leon";	
	return %result;
}

1;
