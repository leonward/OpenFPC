package OFPC::Request;

#########################################################################################
# Copyright (C) 2009 Leon Ward 
# OFPC::Request - Part of the OpenFPC - (Full Packet Capture) project
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
use OFPC::Parse;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
require Exporter;
use Switch;
use Data::Dumper;
use Digest::MD5(qw(md5_hex));
use Digest::SHA;
@EXPORT = qw(ALL);
$VERSION = '0.2';

sub receivefile{

	my $socket=shift;	# Socket
	my $filetype=shift;		# Filetype
	my $svrmd5=shift;	# MD5 of file from server
	my $request=shift;	# Reqiest hashref
	my $debug=0;
	my %result={
		success => 0,
		md5	=> 0,
		message => 0,
		size => 0,
		filename => 0,
		ext => 0,
		filetype => 0,
	};
	print "Debug enabled in Request::receivefile\n" if ($debug);
    print "Expecting MD5 for file is $svrmd5\n" if ($debug); 

	if ( $filetype eq "ZIP" ) {
		$result{'ext'} = ".zip";
	} elsif ( $filetype eq "PCAP" ) {
		$result{'ext'} = ".pcap";
	} else {
		$result{'message'} = "Invalid file filetype $filetype";
		return(\%result);
	}


	# Update $filename with new extension.	
	$request->{'filename'} = $request->{'filename'} . $result{'ext'};
	$result{'filename'} = $request->{'filename'};

	# if savedir is specified, lets add it to the filename
	# A proxy uses a savedir, where as a client doesn't

	my $savefile;
	if (defined $request->{'savedir'}) {
		$savefile = $request->{'savedir'} . "/" . $request->{'filename'};
	} else {
		$savefile = $request->{'filename'};
	}

	# Open file and set socket/file to BIN
        open (FILE,'>',$savefile);
	FILE->autoflush(1);	
        binmode(FILE);
	binmode($socket);

	my $data;
	my $a=0;

	print $socket "READY:\n";
	print "DEBUG: Sent ready marker\n" if ($debug);
	# Do the read from socket, write to file
	while (sysread($socket,$data,1024,0)){
		syswrite(FILE, $data,1024,0);
		$a++;
	}

	close($socket);
	close(FILE);

	unless (open(FILEMD5, '<', $savefile)) {
		$result{'message'} = "Cant open recieved file $savefile";
		$result{'success'} = 0;
		return %result;
	} else {
		$result{'md5'}=Digest::MD5->new->addfile(*FILEMD5)->hexdigest;
		close(PCAPMD5);
	}

	$result{'size'}=`ls -lh $savefile |awk '{print \$5}'`;
	chomp $result{'size'};
	print "DEBUG $savefile size:$result{'size'}\n" if ($debug);

	print "DEBUG File: $savefile on disk is has md5 $result{'md5'}\n" if ($debug);
	print "DEBUG Expected: $svrmd5\n".
	      "DEBUG Got     : $result{'md5'}\n" if ($debug);

	if ($result{'md5'} eq $svrmd5) {
		$result{'success'} = 1;
		$result{'message'} = "Success";
	} else {
		$result{'success'} = 0;
		$result{'message'} = "md5sum mismatch between extracted and recieved file";
	}

	return(\%result);
}

sub request{
	# Take a request hash, and a socket, do as asked and return 
	# a hash of the result

	my $socket=shift;
	my $request=shift;
	my %result=(
			'success' => 0,
			'message' => 0,
			'md5'	=> 0,
			'position' => 'None',
			'filetype' => 0,
			'expected_md5'	=> 0,
			'filename' => 0,
			'size' => 0,
			'time' => 0,
			'table' => 0,
		);					# This is the hash we provide back to the calling function.

	my $debug=0;
	my $event=0;
	my ($protover);
	print Dumper $request if ($debug);
	my $protover="OFPC-v1";		# For future use.

	if ($request->{'logline'}) {
		# Break out the "logline" part of the request into a hash via Parse::parselog.
		# Event details can now be accessed via the hash regardless of event format.

		($event, my $err)=OFPC::Parse::parselog($request->{'logline'});
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
                print "   ---OpenFPC-Request---\n" .
                "   User        $request->{'user'}\n" .
                "   Password    $request->{'password'}\n" .
                "   RID         $request->{'rid'}\n".
                "   Action:     $request->{'action'}\n" .
                "   Device:     $request->{'device'}\n" .
                "   Filename:   $request->{'filename'}\n" .
                "   Tempfile:   $request->{'tempfile'}\n" .
		"   SaveDir:    $request->{'savedir'}\n" .
                "   Filetype:   $request->{'filetype'}\n" . 
                "   Type:       $request->{'type'}\n" .	    # Log type - Need to update this var name to logtype
		"   Comment:	$request->{'comment'}" .
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
		"   SummaryType $request->{'sumtype'}" .
		"   DB Save     $request->{'dbsave'}" ;
		"\n";
        }   

	# Check that a request contains all of the data we require
	# It is expected that any request will have already been sanity checked, but we do it again just incase.

	# The following are required to make any type of request:
	unless ($request->{'user'}) { 
		$result{'success'} = 0;
		$result{'message'} = "No user specified";
		return %result; 
	}

	unless ($request->{'action'} =~ m/(store|fetch|status|summary)/) { 
		$result{'success'} = 0;
		$result{'message'} = "Invalid action $request->{'action'}";
	}

	if ($request->{'action'} =~ m/(fetch)/ ) {
		unless ($request->{'filename'} and $request->{'savedir'} ) {
			$result{'success'} = 0;
			$result{'message'} = "No filename or savedir specified";
		}
	}

	# If we don't have a summary table requested, send the deafult
	if ($request->{'action'} =~ m/(summary)/ ) {
		unless ($request->{'sumtype'}) {
			$request->{'sumtype'} = "top_source_ip_by_volume";
		}
	}
	
	# Make request from Socket
	my $reqstring="$request->{'user'}||" .
			"$request->{'action'}||" .
			"$request->{'device'}||" .
			"$request->{'filename'}||" .
			"$request->{'filetype'}||" .
			"$request->{'type'}||" .
			"$request->{'logline'}||" .
			"$request->{'comment'}||" .
			"$request->{'sumtype'}";

	while(my $connection = $socket->connected) { # While we are connected to the server
        	my $data=<$socket>;
        	print "DEBUG: Waiting for Data\n" if ($debug);
            	chomp $data;
                print "DEBUG: GOT DATA: $data\n\n" if ($debug);

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
						if ( $request->{'showposition'} ){
							print "Queue position $result{'position'}. Wait...\n";
						}
						print "DEBUG: Position: $result{'position'}\n" if ($debug);
                                        } else {
                                                print "DEBUG: Request accepted. Queue position $result{'position'}  Waiting.....\n" if ($debug);
                                        }
                        } case /STATUS/ {
					my $statresp=0;
					my %status=(nodename => 0,
							ofpctype => 0,
							firstpacket => 0,
							firstctx => 0,
							packetspace => 0,
							packetused => 0,
							sessionspace => 0,
							sessionused => 0,
							sessioncount => 0,
							sessionlag => 0,
							savespace => 0,
							saveused => 0,
							comms => 0,
							message => 0,
							ld1 => 0,
							ld5 => 0,
							ld15 => 0,	
							version => 0,
						);

                                        if ($data =~ /^STATUS:\s*(.*)/) {
						$statresp = $1;
                                        }
					($status{'success'},
						$status{'ofpctype'},
                                        	$status{'nodename'},
                                                $status{'firstpacket'},
                                                $status{'firstctx'},
                                                $status{'packetspace'},
                                                $status{'packetused'},
                                                $status{'sessionspace'},
                                                $status{'sessionused'},
                                                $status{'sessioncount'},
                                                $status{'sessionlag'},
                                                $status{'savespace'},
                                                $status{'saveused'},
                                                $status{'ld1'},
                                                $status{'ld5'},
                                                $status{'ld15'},
                                                $status{'comms'},
                                                $status{'message'} ,
						$status{'version'} )= split(/\|\|/,$statresp);	
					return %status;
			} case /RESULTS/ {
					if ($data =~ /^RESULTS:\s*(.*)/) {
						( $result{'success'},
							$result{'message'},
							$result{'time'}) = split(/\|\|/, $1);
					}
					return(%result);
			} case /PCAP/ {
					my $filetype;
                                        print "DEBUG: Incomming PCAP\n" if ($debug);
                                        if ($data =~ /^PCAP:\s*(.*)/) {
						$filetype="PCAP";
						$result{'expected_md5'} = $1;
                                        }
					my $xfer=receivefile($socket,$filetype,$result{'expected_md5'},$request);
					$result{'md5'} = $xfer->{'md5'};
					$result{'size'} = $xfer->{'size'};
					$result{'message'} = $xfer->{'message'};
					$result{'filename'} = $xfer->{'filename'};
					$result{'filetype'} = $filetype;
					if ($xfer->{'success'}) {
						$result{'success'} = 1;
					}
					shutdown($socket,2);
					return %result;
                        } case /ZIP/ {
                                        print "DEBUG: Incomming ZIP\n" if ($debug);
					my $filetype;
                                        if ($data =~ /^ZIP:\s*(.*)/) {
						$filetype="ZIP";
						$result{'expected_md5'} = $1;
                                        }
					my $xfer=receivefile($socket,$filetype,$result{'expected_md5'},$request);
					$result{'md5'} = $xfer->{'md5'};
					$result{'size'} = $xfer->{'size'};
					$result{'message'} = $xfer->{'message'};
					$result{'filename'} = $xfer->{'filename'};
					$result{'filetype'} = $filetype;

					if ($xfer->{'success'}) {
						$result{'success'} = 1;
					}
					shutdown($socket,2);
					return %result;
			} case /TABLE/ {
					my @table=();	
					print "DEBUG: Incomming Table of data\n" if ($debug);
					$result{'success'} = 1;
					while (my $line=<$socket>) {
						my @row=split(/,/, $line);	
						push @table, [ @row ];
					}
 					if ($debug){
                				print "DEBUG: Request: Printing table data ---------------\n";
                				foreach my $foo (@table) {
                        				foreach (@$foo) {
                                        			printf '%20s', "$_";
                        				}   
                				}   
                				print "DEBUG: End Table data -----------------------------\n";
        				}   
					shutdown($socket,$2);
					$result{'table'}=\@table; 
					return %result;
			} case /FILENAME/ {
					if ($data =~ /^FILENAME:\s*(.*)/) {
						$result{'filename'} = $1;
						print "DEBUG: Got Filename: $result{'filename'}\n" if ($debug);
					}
     			} case /QUEUED/ {
                                        if ($data =~ /^QUEUED:*\s*(\d+)/) {
						$result{'position'} = $1;
                                                print "DEBUG: Request accepted. Queue postion $result{'position'}. Disconnecting\n" if ($debug);
                                                shutdown($socket,2);
						$result{'message'} = "In Queue";
						$result{'success'} = 1;
						return %result;
                                        } else {
                                                print "DEBUG: Request accepted. Queue position unknown. Disconnecting\n" if ($debug);
						$result{'success'} = 1;
						$result{'postion'} = "unknown";
                                                shutdown($socket,2);
						return %result;
                                        }
                        } case /ERROR/ {
					my $error;
					if ($data =~ m/ERROR:*\s(.*)/) {
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
				return %result;
                        }
                }
	}

	$result{'message'} = "Something has gone wrong. You should never see this message - Leon";	
	return %result;
}


=head2 mkhash
	Create a SHA1 password
=cut
sub mkhash{
	my $user=shift;
	my $pass=shift;
	my ($digest,$hash);

	die("ERROR: user or pass not set") unless ($user and $pass);
	
	$digest = Digest::SHA->new(1);
	$digest->add($user,$pass);
	$hash = $digest->hexdigest;
	
	return($hash);
}

1;
