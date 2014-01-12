package OFPC::Request;

#########################################################################################
# Copyright (C) 2013 Leon Ward 
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
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
require Exporter;
use Switch;
use Data::Dumper;
use Digest::MD5(qw(md5_hex));
use Digest::SHA;
use JSON::PP;
use Storable qw(dclone);

@EXPORT = qw(ALL);
$VERSION = '0.2';


=head2 wantdebug
	Check if debug is enabled via a shell variable OFPCDEBUG=1
	If so, return a value that enables debug in this function.
=cut
	
sub wantdebug{
	my $var="OFPCDEBUG";

	my $debug=$ENV{$var}; 
	print "DEBUG: Enabling debug via shell variable $var\n" if $debug;
	return($debug); 
}

=head2
	Create a version 2 openfpc structure.
	Returns a href ready for configuration
=cut

sub mkreqv2{
	my %reqv2=(
		user=>{
			text => "Username",
			val => 0,
			required => 1,
		},
		password => {
			text => "Password",
			val => 0,
			required => 1,
		},
		action => {
			text => "Action",
			val => 0,
			required => 1,
		},
		device => {
			text => "Device Name",
			val => 0,
			required => 0,
		},
		logtype => {
			text => "Log Type",
			val => 0,
			required => 0,
		},
		filetype => {
			text => "File type",
			val => 0,
			required => 0,
		},
		logline => {
			text => "Log line",
			val => 0,
			required => 0,
		},
		sip => {
			text => "Source IP",
			val => 0,
			required => 0,
		},
		dip => {
			text => "Destination IP",
			val => 0,
			required => 0,
		},
		spt => {
			text => "Source port",
			val => 0,
			required => 0,
		},
		dpt => {
			text => "Destination port",
			val => 0,
			required => 0,
		},
		bpf => {
			text => "BPF filter",
			val => 0,
			required => 0,
		},
		proto => {
			text => "Protocol",
			val => 0,
			required => 0,
		},
		timestamp => {
			text => "Timestamp",
			val => 0,
			required => 0,
		},
		stime => {
			text => "Start time",
			val => 0,
			required => 0,
		},
		etime => {
			text => "End time",
			val => 0,
			required => 0,
		},
		comment => {
			text => "Comment",
			val => 0,
			required => 0,
		},
		sumtype => {
			text => "Summary Type",
			val => "top_source_ip_by_volume",
			required => 0,
		},
		filename => {
			text => "Filename",
			val => 0,
			required => 0,
		},
		showposition => {
			text => "Show Position",
			val => 0,
			required => 0,
		},
		limit => {
			text => "Results limit",
			val => 20,
			requred => 0,
		},
	);

	return(\%reqv2);
}


sub receivefile{

	my $socket=shift;	# Socket
	my $filetype=shift;	# Filetype
	my $svrmd5=shift;	# MD5 of file from server
	my $r=shift;	# Request hashref
	my $debug=wantdebug();
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
	# XXX May have use in proxy mode	
	$r->{'filename'}{'val'} = $r->{'filename'}{'val'} . $result{'ext'};
	#$result{'filename'} = $r->{'filename'}{'val'} . $result{'ext'};

	# if savedir is specified, lets add it to the filename
	# A proxy uses a savedir, where as a client doesn't

	my $savefile;
	if (defined $r->{'savedir'}{'val'}) {
		$savefile = $r->{'savedir'}{'val'} . "/" . $r->{'filename'}{'val'};
	} else {
		$savefile = $r->{'filename'}{'val'};
	}

	# Open file and set socket/file to BIN
	$result{'filename'} = $savefile;
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
		$result{'message'} = "Cant open received file $savefile";
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

=head request 
	Request version 2. Communicate with the queue daemon and request data.
=cut
sub request{
	# Take a request hash, and a socket, do as asked and return 
	# a hash of the result

	my $socket=shift;
	my $r=shift;		# request href
	my $now=time();
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
	my $debug=wantdebug();
	my $event=0;
	my ($protover);
	my $protover="OFPC-v2";		# For future use.

	print "DEBUG: Debug enabled in reqest\n" if ($debug);

	# Selecting buffer device related to event src isn't dont yet.
	if ($debug) {
		foreach(keys %$r) {
			print "      $r->{$_}{'text'}:\t $r->{$_}{'val'}\n" if $r->{$_}{'val'};
		}
    } 
    print "-------------------\n" if $debug;

	# Check that a request contains all of the data we require
	# It is expected that any request will have already been sanity checked, but we do it again just incase.



	# If no timestamp, stime or etime have been specified, set a default range to search
	unless ($r->{'timestamp'}{'val'}) {
		if ($r->{'stime'}{'val'} and $r->{'etime'}{'val'}) {
			print "DEBUG: stime and etime are set\n" if $debug;
		} else {
			print "DEBUG: Neither timestamp or stime/etime are set, setting timestamp to $now, it was $r->{'timestamp'}{'val'}\n" if $debug;

			$r->{'timestamp'}{'val'} = $now;
		}
	} else {
		print "DBEUG: Timestamp set" if $debug;
	}

	foreach(keys %$r) {
		if ($r->{$_}{'required'}) { 
			unless ($r->{$_}{'val'}) { 
				$result{'message'} = "ERROR: $r->{$_}{'text'} is manditory for any type of request";
				return %result;
			}
		}	
    } 

	if ($r->{'action'}{'val'} =~ m/(fetch)/ ) {
		unless ($r->{'filename'}{'val'} and $r->{'savedir'}{'val'} ) {
			$result{'success'} = 0;
			$result{'message'} = "No filename or savedir specified";
		}
	}

	# Remove the password from the JSON sent, we don't want to leak it
	my $r_tmp=dclone($r);
	$r_tmp->{'password'}{'val'} = 0;
	my $rj=encode_json($r_tmp);

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
			case /OFPC-v2 OK/ { 
				print "DEBUG: Sending User $r->{'user'}{'val'}\n" if ($debug);
				print $socket "USER: $r->{'user'}{'val'}\n" ;
			}   
			case /CHALLENGE/ {
				if ($data =~ /CHALLENGE:\s+(\d+)/) {
					my $challenge=$1;
					print "DEBUG: Got Challenge $1\n" if ($debug);
					my $response=md5_hex("$challenge$r->{'password'}{'val'}");
					print "DEBUG: Sending MD5 based Response : $response\n" if ($debug);
					print $socket "RESPONSE:$response\n";
				} else {
					print "DEBUG: CHALLENGE ERROR\n" if ($debug);
					print $socket "ERROR Problem with challenge\n";
				}
			} 
			case /WAIT/ {
				if ($data =~ /^WAIT:*\s*(\d+)/) {
					$result{'position'} = $	1;
					if ( $r->{'showposition'}{'val'} ){
						print "Queue position $result{'position'}. Wait...\n";
					}
					print "DEBUG: Position: $result{'position'}\n" if ($debug);
				} else {
					print "DEBUG: Request accepted. Queue position $result{'position'}  Waiting.....\n" if ($debug);
				}
			} 
			case /STATUS/ {
				my $sr=0;
				if ($data =~ /^STATUS:\s*(.*)/) {
					if ($sr = decode_json($1)) {
						return(%$sr);
					}
				} else {
					print "ERROR: Recieved status response that didn't decode\n";
				}
			} 
			case /RESULTS/ {
				if ($data =~ /^RESULTS:\s*(.*)/) {
					( $result{'success'},
					$result{'message'},
					$result{'time'}) = split(/\|\|/, $1);
				}
				return(%result);
			} 
			case /PCAP/ {
				my $filetype;
				print "DEBUG: Incomming PCAP\n" if ($debug);
				if ($data =~ /^PCAP:\s*(.*)/) {
					$filetype="PCAP";
					$result{'expected_md5'} = $1;
					print "DEBUG: Expcting md5 of pcap to be $result{'expected_md5'}\n" if $debug;
				}
				my $xfer=receivefile($socket,$filetype,$result{'expected_md5'},$r);
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
			} 
			case /ZIP/ {
				print "DEBUG: Incomming ZIP\n" if ($debug);
				my $filetype;
				if ($data =~ /^ZIP:\s*(.*)/) {
					$filetype="ZIP";
					$result{'expected_md5'} = $1;
				}
				my $xfer=receivefile($socket,$filetype,$result{'expected_md5'},$r);
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
			} 
			case /TABLE/ {
				my @table=();	
				print "DEBUG: Incomming Table of data\n" if ($debug);
				$result{'success'} = 1;
				my $tj=<$socket>;
				my $t;
				if (decode_json($tj)) {
					print "Decodedi JSON\n" if $debug;
				} else {
					print "Failed to decode JSON table data recieved\n" if $debug;
				}

				shutdown($socket,$2);
				$result{'table'}=$tj; 
				return %result;
			} 
			case /FILENAME/ {
				if ($data =~ /^FILENAME:\s*(.*)/) {
					$result{'filename'} = $1;
					print "DEBUG: Got Filename: $result{'filename'}\n" if ($debug);
				}
			} 
			case /QUEUED/ {
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
			} 
			case /ERROR/ {
				my $error;
				if ($data =~ m/ERROR:*\s(.*)/) {
					$result{'message'} = $1;
					print "DEBUG: Got error: $result{'message'} :closing connection\n" if ($debug);
				}
				shutdown($socket,2);
				return %result;
			} 
			case /AUTH OK/ {
				# If auth is okay, send the request
				print "DEBUG: Password OK\n" if ($debug);
				print $socket "REQ:$rj\n";
				print "DEBUG: REQ JSON submitted\n" if ($debug);
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

	die("ERROR: Can't make a hash without user and pass set") unless ($user and $pass);
	
	$digest = Digest::SHA->new(1);
	$digest->add($user,$pass);
	$hash = $digest->hexdigest;
	
	return($hash);
}

1;
