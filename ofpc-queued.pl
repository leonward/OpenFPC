#!/usr/bin/perl -I .

#########################################################################################
# Copyright (C) 2010 Leon Ward 
# openfpc-queued.pl - Part of the OpenFPC - (Full Packet Capture) project
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
use Switch;
use threads;
use threads::shared;
use Thread::Queue;
use IO::Socket;
use Digest::MD5(qw(md5_hex));
use Getopt::Long;
use POSIX qw(setsid);		# Required for daemon mode
use Data::Dumper;
use File::Temp(qw(tempdir));
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
use Filesys::Df;
use Sys::Syslog;
use ofpc::Parse;
use ofpc::Request;

=head1 NAME

ofpc-queued.pl - Queue and process extract requests from local and remote PCAP storage devices

=head1 VERSION 

0.2

=cut
my $openfpcver="0.2";

my ($queuelen,$debug,$verbose,$rid,%config,%userlist,$help);
my $queue = Thread::Queue->new();	# Queue shared over all threads
my $mrid : shared =1; $mrid=1;	# Master request counter. Quick way to identify  requests
my %pcaps: shared =();
my %route: shared =();
my $CONFIG_FILE=0;
my $daemon=0;		# NOT DONE YET
$verbose=0;
$debug=0;

sub showhelp{
	print <<EOF

   * ofpc-queued.pl *
   Part of the OpenFPC project.

   --daemon  or -d		Daemon mode
   --config  or -c <file>	Config file  
   --help    or -h		Show help
   --verbose or -v		Verbose logging
   --debug  	 		Show debug data
  
EOF
}

=head2 pipeHandler
	Deal with clients that disappear rather than have perl die.
=cut

sub pipeHandler{
    my $sig = shift @_;
    print "SIGPIPE -> Bad client went away! $sig \n\n" if ($verbose);
}

=head2 closedown
	Shutdown in a clean way.
=cut

sub closedown{
	my $sig=shift;
	wlog("Shuting down by request via $sig\n");
	File::Temp::cleanup();
	unlink($config{'OFPC_Q_PID'});
	closelog;
	exit 0;
}

=head2 getrequestid
	Generate a "unique" request ID for the extraction request
	It's pretty basic right now, but it's here in case I want
	to make each rid unique over program restarts
=cut

sub getrequestid{
	$mrid++;	
	return($mrid);
}

=head2 decoderequest
	Take the OFPC request, and provide a hash(ref) to the decoded data.
	Example of a OFPC request:
	ofpc||fetch||||/tmp/foo.pcap||||auto||ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 dpt:22 proto:tcp time:1274864808 msg:Some freeform text||Some comment text
=cut

sub decoderequest($){
        my $rawrequest=shift;
        my %request=(   user     =>     0,
                        action   =>     0,
			rid	 =>	0,
                        device   =>     0,
                        filename =>     0,
			tempfile =>	0,
                        filetype =>     0,
                        logtype  =>     0,
                        logline  =>     0,
			sip	=>	0,
			dip	=>	0,
			proto	=>	0,
			spt	=>	0,
			dpt	=>	0,
			msg	=>	0,
			rtime	=>	0,
			timestamp =>	0,
			stime	=>	0,
			etime	=>	0,
			comment =>	0,
			valid   =>	0,
        );

        my @requestarray = split(/\|\|/, $rawrequest);
        my $argnum=@requestarray;
	$request{'rtime'} = gmtime();

        unless ($argnum == 8 ) {
                if ($debug) {
                        print "-D  Bad request, only $argnum args. Expected 8\n";
                }
		$request{'msg'} = "Bad request. Only $argnum args. Expected 8\n";
                return(\%request);
        }

	# Each request element is seprated by a double-pipe - ||
        ($request{'user'},			# OFPC user
		$request{'action'},		# Action (store,status,fetch,etc)
		$request{'device'},		# Device to request from i.e ofpc-slave
		$request{'filename'},		# Filename to save file as 
		$request{'filetype'},		# Filetype zip or pcap?
		$request{'logtype'},		# Type of log being processed
		$request{'logline'},		# The log-line (including one made from session identifiers
		$request{'comment'}		# User comments
		) = split(/\|\|/, $rawrequest);

	# Check logline is valid
	my ($eventdata, $error)=ofpc::Parse::parselog($request{'logline'});
	unless ($eventdata) {
		wlog("ERROR: Cannot parse logline-> $error");
		return(\%request);
	} else {
		# Append the session that is being requested to the hash that is the request itself
		$request{'sip'} = $eventdata->{'sip'};
		$request{'dip'} = $eventdata->{'dip'};
		$request{'spt'} = $eventdata->{'spt'};
		$request{'dpt'} = $eventdata->{'dpt'};
		$request{'msg'} = $eventdata->{'msg'};
		$request{'timestamp'} = $eventdata->{'timestamp'};
		$request{'stime'} = $eventdata->{'stime'};
		$request{'etime'} = $eventdata->{'etime'};
		$request{'proto'} = $eventdata->{'proto'};
	}
	unless ($request{'comment'}) {
		$request{'comment'} = "No comment";
	}

	# Default to PCAP file if filetype not specified
	unless ($request{'filetype'}) {
		$request{'filetype'} = "PCAP";
	}

	#if ($debug) {
	#	print "DEBUG Dumping request in decoderequest\n";
	#	print Dumper %request;
        #}

	# Check action: Valid actions are:

	# fetch 	Fetch pcap and return to client/server
	# store		Request data for extraction, and disconnect.
	# status	Provide status of slave device (FUTURE)
	# replay	Replay traffic (FUTURE)

	$request{'action'} = lc $request{'action'};
	$request{'rid'} = getrequestid;

	if ($request{'action'} =~ m/(fetch|store|status)/) {
		wlog("DECOD: Recieved action $request{'action'}");
		wlog("DECOD: User $request{'user'} assigned RID: $request{'rid'} for action $request{'action'}. Comment: $request{'comment'} Filetype : $request{'filetype'}");
		$request{'valid'} = 1;
        	return(\%request);
	} else {
		wlog("DECOD: Recieved invalid action $request{'action'}");
		$request{'msg'} = "recieved invalid action $request{'action'}";
		return(\%request);
	}
}


=head2 prepfile 
	prepare a file to deliver back to the client.
	Call with:
		\$request
	This consists of:
		- Checking if we are to queue it up for later or do it now
		- If master-Check the routing to see if we need to fragment it and re-insert for each slave
		- Call the extract functions (if we are to do it now)
		- Return a hashref containing
		( success => 0,
		  filename => 0,
		  message => 0,
		  filetype => 0,
		  md5 => 0,
		  size => 0,
		)

		success 1 = Okay 0= Fail
		filename = Name of file (no path!)
		message = Error message
		filetype "PCAP" = pcap file "ZIP" = zip file
=cut

sub prepfile{
	my $request=shift;
	my @ziplist=();		# List of files to zip up
	my $multifile=0;
	my $meta=0;
	my %prep=(
			success => 0,
			filename => 0,
			message => 0,
			filetype => "PCAP",
			md5 => 0,
			size => 0,
	);	

	# If a zip file is requested, set prep to gather a zip
	if ($request->{'filetype'} eq "ZIP") {
		$multifile=1;
		$prep{'filetype'} = "ZIP";		
	}

	# If we are master, check if we need to frag this req into smaller ones, and get the data back from each slave
	# If we are slave, do the slave action now (rather than enqueue if we were in STORE mode)
	# Check if we want to include the meta-text
	# Return the filename of the data that is to be sent back to the client.

	if ( $config{'MASTER'} ) {
		# Check if we can route this request
		unless (open METADATA , '>', "$config{'SAVEDIR'}/$request->{'tempfile'}.txt")  { 
			wlog("PREP: ERROR: Unable to open MetaFile $config{'SAVEDIR'}/$request->{'tempfile'}.txt for writing");
			$prep{'message'} = "Unable to open Metadata file - Cant continue\n";
			return(\%prep);	
		}
        	print METADATA "###################################\nOFPC-Master request report\n" .
			"User: $request->{'user'}\n" .
                       	"User comment: $request->{'comment'}\n" .
                       	"Time: $request->{'rtime'}\n";

 		(my $slavehost,my $slaveport,my $slaveuser,my $slavepass)=routereq($request->{'device'});
		unless ($slavehost) { 	# If request isn't routeable....
					# Request from all devices
			$multifile=1;	# Fraged request will be a multi-file return so we use a ZIP to combine
			$prep{'filetype'} = "ZIP";
			foreach (keys %route) {
 				($slavehost,$slaveport,$slaveuser,$slavepass)=routereq($_);
				$request->{'slavehost'} = $slavehost;
				$request->{'slaveuser'} = $slaveuser;
				$request->{'slaveport'} = $slaveport;
				$request->{'slavepass'} = $slavepass;

				my $result=domaster($request);
				if ($result->{'success'}) {
					wlog("Adding $result->{'filename'} to zip list") if ($verbose);
					push (@ziplist, $result->{'filename'});
				} else {
					$prep{'message'} = $result->{'message'};
					wlog("Error: $result->{'message'}");

				}

				print METADATA "-------------------\n";
				print METADATA "Host    : $slavehost\n";
				print METADATA "Port    : $slaveport\n";
				print METADATA "User    : $slaveuser\n";
				print METADATA "Filename: $result->{'filename'}\n";
				print METADATA "Size    : $result->{'size'}\n";
				print METADATA "MD5     : $result->{'md5'}\n";
				print METADATA "Error   : $result->{'message'}\n";
			}
		} else { 					# Routeable, do the master action 
			$request->{'slavehost'} = $slavehost;
			$request->{'slaveuser'} = $slaveuser;
			$request->{'slaveport'} = $slaveport;
			$request->{'slavepass'} = $slavepass;

			my $result=domaster($request);

			if ($result->{'success'}) {
				$prep{'success'} = 1;
				$prep{'md5'} = $result->{'md5'};
				$prep{'filetype'} = "PCAP";
				$prep{'filename'}="$result->{'filename'}";
       				push (@ziplist, $result->{'filename'});
				wlog("PREP: Added $result->{'filename'} to zip list") if ($verbose);
			} else {
				$prep{'message'} = $result->{'message'};
				wlog("Error: $result->{'message'}");
			}

			print METADATA "-------------------\n";
			print METADATA "Host: $slavehost\n";
			print METADATA "Port: $slaveport\n";
			print METADATA "User: $slaveuser\n";
			print METADATA "Filename: $result->{'filename'}\n";
			print METADATA "Size    : $result->{'size'}\n";
			print METADATA "MD5     : $result->{'md5'}\n";
			print METADATA "Error   : $result->{'message'}\n";

		}
        	close METADATA;
		push (@ziplist,"$request->{'tempfile'}.txt");

	} else { 	# Do slave stuff, no routing etc just extract the data and make a report
   		my $result = doslave($request,$rid);

		if ($result->{'success'}) {
			$prep{'success'} = 1;
			$prep{'filename'} = $result->{'filename'};
			$prep{'md5'} = $result->{'md5'};
			$prep{'size'} = $result->{'size'};
		} else {
			$prep{'message'} = $result->{'message'};
		}

		unless (open METADATA , '>', "$config{'SAVEDIR'}/$request->{'tempfile'}.txt" ) { 
			wlog("PREP: ERROR: Unable to open MetaFile $config{'SAVEDIR'}/$request->{'tempfile'}.txt for writing");
			$prep{'message'} = "Unable to open Metadata file - Cant continue\n";
			return(\%prep);	
		}
        	print METADATA "OFPC-slave request report\n" .
			"User: $request->{'user'}\n" .
                       	"User comment: $request->{'comment'}\n" .
                       	"Time: $request->{'rtime'}\n" .
			"Filename: $result->{'filename'}\n" .
			"Size    : $result->{'size'}\n" .
			"MD5     : $prep{'md5'}\n" .
			"Error   : $result->{'message'}\n" ;
		close(METADATA);
		push(@ziplist,"$request->{'tempfile'}.txt");
		push(@ziplist,$request->{'tempfile'});
	}

	# Now we have the file(s) we want to rtn to the client, lets zip if reqd
	if ($multifile) {
		$prep{'filetype'} = "ZIP";
		my $zip = Archive::Zip->new();
		foreach my $filename (@ziplist) {
			if ( -f "$config{'SAVEDIR'}/$filename" ) {
				$zip->addFile("$config{'SAVEDIR'}/$filename","$filename");
			} else {
				wlog("ZIP : Cant find $config{'SAVEDIR'}/$filename to add to zip! - Skipping"); 
			}
		}
		if ($zip->writeToFileNamed("$config{'SAVEDIR'}/$request->{'tempfile'}.zip") !=AZ_OK ) {
			wlog("PREP: ERROR: Problem creating $config{'SAVEDIR'}/$request->{'tempfile'}.zip");
		} else {
			wlog("PREP: Created $config{'SAVEDIR'}/$request->{'tempfile'}.zip");
			$prep{'filename'}="$request->{'tempfile'}.zip";
			$prep{'success'} = 1;
			$prep{'md5'} = getmd5("$config{'SAVEDIR'}/$prep{'filename'}");
		}
	}
	return(\%prep);

}

=head2 getmd5
	Get the md5 for a file. 
	Takes, filename (including path)
	Returns the md5sum 
=cut

sub getmd5{

	my $file=shift;
	unless (open(MD5, '<', $file)) {
		wlog("MD5: ERROR: Cant open file $file to get MD5");
		return 0;
	}
	my $md5=Digest::MD5->new->addfile(*MD5)->hexdigest;
	wlog("MD5: $file => $md5") if ($verbose);
	close(MD5);
	return($md5);
}

=head2 getstatus
	Get the status of a slave, or bunch of slaves if this is a master device
=cut

sub getstatus{
	my $request=shift;
	my $exec=0;
	my %stat = ( 
		success => 0,
		ofpctype => 0,		# Master or slave
		nodename => 0,		# Name of the node
		firstpacket => 0,	# Oldest packet timestamp
		packetspace => 0,	# Space available in PCAP partition
		packetused => 0,
		sessionspace => 0,	# Space available in session data partition
		sessionused => 0,	# Space consumed by session data (excluding DB)
		savespace => 0,		# Space availabe in the savepath
		saveused => 0,		# Space availabe in the savepath
		comms => 0,		# Communication with slaves (master only)
		ld1 => 0,		# UNIX load average 1,5, and 15
		ld5 => 0,
		ld15 => 0,
		message => 0,		# Message for error text
	);

	unless ($config{'MASTER'}) { 	# Process as a slave. Don't check master specific stuff like comms
		$stat{'ofpctype'} = "SLAVE";
		$stat{'nodename'} = $config{'NODENAME'};

		# Get timestamp of oldest pcap buffer
		opendir(DIR,$config{'BUFFER_PATH'});
		my @files=readdir(DIR);
		@files=sort(@files);

		# A sorted dir could also include other files. We can apply a check for the daemonlogger prfix
		# to make sure we don't end up with some other crap, or ".",".." etc

		my $oldestfile=0;
		while ($oldestfile !~ /$config{'NODENAME'}-pcap/) {
			$oldestfile=shift(@files);
		}

		if ( $oldestfile =~ /$config{'NODENAME'}-pcap\.([0-9]+)/ ) {
			$stat{'firstpacket'} = $1;
		}

		# Get disk space info
		my $packetref=df("$config{'BUFFER_PATH'}");
		$stat{'packetspace'} = $packetref->{'per'};
		$stat{'packetused'} = $packetref->{'used'};
		
		my $sessionref=df("$config{'SESSION_DIR'}");
		$stat{'sessionspace'} = $sessionref->{'per'};
		$stat{'sessionused'} = $sessionref->{'used'};

		my $saveref=df("$config{'SAVEDIR'}");
		$stat{'savespace'} = $saveref->{'per'};
		$stat{'saveused'} = $saveref->{'used'};
	
		# Grab uptime data
		my $uptime=`uptime`;
		chomp $uptime;
		if ($uptime =~ /load average.*:\s*([0-9]\.[0-9]+),*\s*([0-9]\.[0-9]+),*\s*([0-9]\.[0-9]+)/){ 
			$stat{'ld1'} = $1;
			$stat{'ld5'} = $2;
			$stat{'ld15'} = $3;
		}

		# Check we are providing back some valid data

		if ($stat{'packetspace'} and $stat{'savespace'} and
				$stat{'sessionspace'} and
				$stat{'ld1'} and
				$stat{'ld5'} and
				$stat{'ld15'} and
				$stat{'nodename'} ) {
			
			$stat{'success'} = 1; 	
		}


	} else {
		wlog("Recieved MASTER STATUS request - Not implemented");
		$stat{'message'} = "Master status not implemented yet";
		$stat{'ofpctype'} = "MASTER";
	}

	return(\%stat);
}


=head2 comms
	Communicate with the client, and if a valid request is made add it on to the processqueue
=cut

sub comms{
	my ($client) = @_;
	my $client_ip=$client->peerhost;
	my %state=(
		version => 0,
		user	=> 0,
		auth	=> 0,
		action	=> 0,
		logline	=> 0,
		filename => 0,
		response => 0,
	);

	# Print banner
        print $client "OFPC READY\n";
  	while (my $buf=<$client>) {
    		chomp $buf;
    		$buf =~ s/\r//;
	    	#print "$client_ip -> Got data $buf :\n" if ($debug);
	        switch($buf) {
			case /USER/ {	# Start authentication provess
				if ($buf =~ /USER:\s+([a-zA-Z1-9]+)/) {
					$state{'user'}=$1;	
					wlog("COMMS: $client_ip: GOT USER $state{'user'}");
					if ($userlist{$state{'user'}}) {	# If we have a user account for this user
						my $clen=20; #Length of challenge to send
                        			my $challenge="";
                        			for (1..$clen) {
                                			$challenge="$challenge" . int(rand(99));
                        			}
                        			print "DEBUG: $client_ip: Sending challenge: $challenge\n" if ($debug);
                        			print $client "CHALLENGE: $challenge\n";
                        			print "DEBUG: $client_ip: Waiting for response to challenge\n" if ($debug);
                        			#my $expResp="$challenge$userlist{$reqh->{'user'}}";
                        			$state{'response'}=md5_hex("$challenge$userlist{$state{'user'}}");
					} else {
						wlog("COMMS: $client_ip: AUTH FAIL: Bad user: $state{'user'}");
						print $client "AUTH FAIL: Bad user $state{'user'}\n";
					}
				} else {
					wlog("COMMS: $client_ip: Bad USER: request $buf. Sending ERROR");
					print $client "AUTH FAIL: Bad user $state{'user'}\n";
				}
			} case /RESPONSE/ {
				print "DEBUG: $client_ip: Got RESPONSE\n" if ($debug);
				if ($buf =~ /RESPONSE:*\s*(.*)/) {
					my $response=$1;
					if ($debug) {
                                		print "DEBUG: $client_ip: Expected resp: $state{'response'}-\n";
                                		print "DEBUG: $client_ip: Real resp    : $response\n";
                        		}
                        		# Check response hash
                        		if ( $response eq $state{'response'} ) {	
						wlog("COMMS: $client_ip: Pass Okay");
						$state{'response'}=0;		# Reset the response hash. Don't know why I need to, but it sounds like a good idea. 
						$state{'auth'}=1;		# Mark as authed
						print $client "AUTH OK\n";
					} else {
						wlog("COMMS: $client_ip: Pass Bad");
						print $client "AUTH FAIL\n";
					}
				} else {
					print "DEBUG $client_ip: Bad USER: request $buf\n " if ($debug);
					print $client "ERROR: Bad password request\n";
				}
			} 
			case /ERROR/ {
                                wlog("DEBUG $client_ip: Got error. Closing connection\n");
                                shutdown($client,2);

			} 
			case /^REQ/ {	
				my $reqcmd;
				# OFPC request. Made up of ACTION||...stuff
				if ($buf =~ /REQ:\s*(.*)/) {
					$reqcmd=$1;
					#print "DEBUG: $client_ip: REQ -> $reqcmd\n" if ($debug);
					my $request=decoderequest($reqcmd);
					if ($request->{'valid'} == 1) {					# Valid request then...		
						# Generate a rid (request ID for this.... request!).
						# Unless action is something we need to wait for, lets close connection
						my $position=$queue->pending();
						if ("$request->{'action'}" eq "store") {
							# Create a tempfilename for this store request
							$request->{'tempfile'}=time() . "-" . $request->{'rid'} . ".pcap";
							print $client "FILENAME: $request->{'tempfile'}\n";

							$queue->enqueue($request);
							#Say thanks and disconnect
							print "DEBUG: $client_ip: RID: $request->{'rid'}: Queue action requested. Position $position. Disconnecting\n" if ($debug);
							print $client "QUEUED: $position\n";
							shutdown($client,2);

						} elsif ($request->{'action'} eq "fetch") {
							# Create a tempfilename for this store request
							$request->{'tempfile'}=time() . "-" . $request->{'rid'} . ".pcap";
							wlog("COMMS: $client_ip: RID: $request->{'rid'} Request OK -> WAIT!\n");
							my $prep = prepfile($request);
							my $xferfile=$prep->{'filename'};

							if ($prep->{'success'}) {
								wlog("COMMS: $request->{'rid'} $client_ip Sending File:$config{'SAVEDIR'}/$xferfile MD5: $prep->{'md5'}");
								# Get client ready to recieve binary PCAP or zip file
								if ($prep->{'filetype'} eq "ZIP") {
									print $client "ZIP: $prep->{'md5'}\n";
								} elsif ($prep->{'filetype'} eq "PCAP") {
									print $client "PCAP: $prep->{'md5'}\n";
								} else {
									print "SENT OTHER $prep->{'filetype'}\n";
									print $client "ERROR: Bad filetype extracted : $prep->{'filetype'}\n";
	                        					shutdown($client,2);	
								}
								$client->flush();

								# Wait for client to share its ready state
								# Any data sent from the client will be fine.

								my $ready=<$client>;
								open(XFER, '<', "$config{'SAVEDIR'}/$xferfile") or die("cant open pcap file $config{'SAVEDIR'}/$xferfile");
								binmode(XFER);
								binmode($client);

								my $data;
								# Read and send pcap data to client
								my $a=0;
								while(sysread(XFER, $data, 1024)) {
									syswrite($client,$data,1024);
									$a++;
								}
								wlog("COMMS: Uploaded $a x 1KB chunks\n");
								close(XFER);		# Close file
	                        				shutdown($client,2);	# CLose client

								wlog("COMMS: $client_ip Request: $request->{'rid'} Transfer complete");
							} else {
								print $client "ERROR: $prep->{'message'}\n";
	                        				shutdown($client,2);	# CLose client
							} 
						} elsif ($request->{'action'} eq "status") {
							wlog ("COMMS: $client_ip Recieved Status Request");
							my $status=getstatus($request);
							my $statmsg="$status->{'success'}||" .
									"$status->{'ofpctype'}||".
									"$status->{'nodename'}||" .
									"$status->{'firstpacket'}||" .
									"$status->{'packetspace'}||" .
									"$status->{'packetused'}||" .
									"$status->{'sessionspace'}||" .
									"$status->{'sessionused'}||".
									"$status->{'savespace'}||" .
									"$status->{'saveused'}||".
									"$status->{'ld1'}||" .
									"$status->{'ld5'}||" .
									"$status->{'ld15'}||" .
									"$status->{'comms'}||" .
									"$status->{'message'}||" .
									"\n";
							print $client "STATUS: $statmsg";
	                        			shutdown($client,2);
						}
					} else {
						wlog("COMMS: $client_ip: BAD request $request->{'msg'}");
						print $client "ERROR $request->{'msg'}\n";
	                        		shutdown($client,2);
					}
				} else {
					wlog("DEBUG: $client_ip: BAD REQ -> $reqcmd");
					print $client "ERROR bad request\n";
	                        	shutdown($client,2);
				}

			} case /OFPC-v1/ {
				print "DEBUG $client_ip: GOT version, sending OFPC-v1 OK\n" if ($debug);
	       	                print $client "OFPC-v1 OK\n" ;

			} else {
				print "DEBUG: $client_ip : Unknown request. ->$buf<-\n" if ($debug);	
	                        #shutdown($client,2);
	                }
	        }
		#print "DEBUG: $client_ip:  Waiting for data\n" if($debug);
  	}
	close $client;

}

=head2 wlog
	Write the string passed to the function as a log
	e.g. wlog("Something just went down");
=cut
                        
sub wlog{
        my $msg =  shift;

        chomp $msg;
        my $gmtime=gmtime();
	my $logdata = $config{'NODENAME'}  . " " .  $msg;
        unless ($daemon) {
                print "$gmtime GMT: $logdata\n";
        } 
	syslog("info",$logdata);
}

=head frageq
	Take a single request, and re-insert it in the queue but for every known device.
	This isn't used right now, I was testing some concepts out.
=cut

sub fragreq{
	print "Fraging request\n";

	my $request=shift;
	foreach my $device (keys %route){
		$request->{'rid'} = getrequestid;
		$request->{'device'} = $device;
        	my $qlen=$queue->pending();     # Length of extract queue
		print "Qlen is $qlen\n";
		# Inject a a sub-request to slave that exists
		print "Adding sub-request RID $request->{'rid'} to $request->{'device'} \n";
		$queue->enqueue($request);
        	$qlen=$queue->pending();     # Length of extract queue
		print "Qlen is $qlen\n";
	}
	# If original req is WAITING, report back it's fraged so it can move on.
}

=head routereq
	Find device to make request from, and calculate the correct user/pass
	expects $device
	returns $slavehost,$slaveport,$salveuser,$slavepass
=cut

sub routereq{
	my $device=shift;
	my $slavehost=0;
	my $slaveport=0;
	my $slaveuser=0;
	my $slavepass=0;
	my $slavevalue=0;
	if (exists $route{$device} ) {
		$slavevalue=$route{$device};
		($slavehost, $slaveport, $slaveuser, $slavepass) = split(/:/, $slavevalue);
		wlog("ROUTE: Routing request to : $device ( $slavehost : $slaveport User: $slaveuser )");
	} else {
		wlog("ROUTE: No ofpc-route entry found for $device in routing table\n");
		return(0,0,0,0);
	}
		
	unless ($slavehost and $slaveport and $slavepass and $slaveuser) {
		wlog("ROUTE: ERROR: Unable to pass route line $slavevalue");
		return(0,0,0,0);		
	} else {
		return($slavehost,$slaveport,$slaveuser,$slavepass);
	}
}

=head2 domaster
	The OFPC "Master" action.
	A Master device proxies the request from the client to a slave, and sends the data back to the client.
	The Master action allows ofpc to scale out rather than up, and hopefully be pretty scalable (to be confirmed!)

	Master mode is OUT OF SCOPE for the initial release, but I wanted to make sure that it could function sooner rather than later.
	I had this working in a few tests, so theory is Okay, but needs some more planing before release.

	Expects a hashref of the request
	Returns a hash of result data
	%result( 
		filename => 0,
		md5 => 0,
		size => 0,
		success => 0,
		message => 0,
	)
=cut

sub domaster{
	
	my $request=shift;
	my %result=(
		message => "None",
		success => 0,
		filename => 0,
		size => 0,
		md5 => 0,
	);

	my $slavesock = IO::Socket::INET->new(
                                PeerAddr => $request->{'slavehost'},
                                PeerPort => $request->{'slaveport'},
                                Proto => 'tcp',
                                );

	unless ($slavesock) { 
		wlog("MASTR: Unable to open socket to slave $request->{'slavehost'}:$request->{'slaveport'}");
		$result{'message'} = "Node: $config{'NODENAME'} unable to connect to slave $request->{'slavehost'}:$request->{'slaveport'}";
		$result{'success'} = 0;	
		return(\%result);
	}
	# This is a master request, we don't want the user to control what file we will
	# write on the master. Create our own tempfile.
	$request->{'filename'}="M-$request->{'slavehost'}-$request->{'slaveport'}-" . time() . "-" . $request->{'rid'};
	#$request->{'filename'}="M-$request->{'slavehost'}-$request->{'slaveport'}-" . time() . "-" . $request->{'rid'} . ".pcap";
	$request->{'user'} = $request->{'slaveuser'};
	$request->{'password'} = $request->{'slavepass'};
	$request->{'savedir'} = $config{'SAVEDIR'};
	%result=ofpc::Request::request($slavesock,$request);
	
	# Return the name of the file that we have been passed by the slave
	if ($result{'success'} == 1) {
		wlog("DEBUG: Master got $result{'filename'} MD5: $result{'md5'} Size $result{'size'} from $request->{'device'} ($request->{'slavehost'})\n");
		return(\%result);
	} else {
		wlog("Problem with extract: Result: $result{'success'} Message: $result{'message'}");
		return(\%result);
	}
}

=head2 doslave
	The slave action is where the real extraction work takes place.
	It takes a decoded request as it's input, and returns a filename when the extraction has been done.
	
	returns a hash of
		( success => 0,
		  filename => 0,
		  md5 => 0,
		  size => 0,
		  message => 0,
		)
=cut

sub doslave{
	# A slave action is one that will be processed on this device.
	# It will perform the action itself rather than pass it on to another device.

	my $extractcmd;
	my $request=shift;
	my @cmdargs=();
	my %result=( filename => 0,
			success => 0,
			message => 0,
			md5 => 0,
			size => 0,
		);

	wlog("SLAVE: Request: $request->{'rid'} User: $request->{'user'} Action: $request->{'action'}");
	my $bpf=mkBPF($request);
	print "DEBUG: BPF is $bpf\n" if ($debug);

	my @pcaproster=findBuffers($request->{'timestamp'}, 5);

	print "DEBUG: Got buffers @pcaproster\n" if ($debug);

	(my $filename, my $size, my $md5) = doExtract($bpf,\@pcaproster,$request->{'tempfile'});
	if ($filename) {
		$result{'filename'} = $filename;
		$result{'success'} = 1;
		$result{'message'} = "Success";
		$result{'md5'} = $md5;
		$result{'size'} = $size;
		wlog("SLAVE: Extraction complete: Result: $filename, $size, $md5");   
	} else {
		wlog("SLAVE: Problem found while performing doExtract Result: $filename, $size, $md5");   
	}
	
	# Create extraction Metadata file
	
	unless ( open METADATA , '>', "$config{'SAVEDIR'}/$filename.txt" ) { 
			wlog("PREP: ERROR: Unable to open MetaFile $config{'SAVEDIR'}/$request->{'tempfile'}.txt for writing");
			$result{'message'} = "Unable to open Metadata file  $config{'SAVEDIR'}/$request->{'tempfile'}.txt for writing";
			return(\%result);
	}
	print METADATA "Extract Report - Slave action\n";
	print METADATA "User: $request->{'user'}\n" .
			"Filename: $request->{'filename'}\n" .
			"MD5: $md5\n" .
			"Size: $size\n" .
			"User comment: $request->{'comment'}\n" .
			"Time: $request->{'rtime'}\n";
	close METADATA;

	# Return the name of the file that we have extracted
	
        return(\%result);
}

=head2 runq
	Runq waits for an entry to appear in the extraction queue, and then takes action on it.
=cut

sub runq {
	while (1) {
        	sleep(1);                       # Pause between polls of queue
        	my $qlen=$queue->pending();     # Length of extract queue
        	if ($qlen >= 1) {
			my $request=$queue->dequeue();
                	wlog("RUNQ : Found request: $request->{'rid'} Queue length: $qlen");
                	wlog("RUNQ : Request: $request->{'rid'} User: $request->{'user'} Found in queue:");
			if ($config{'MASTER'}) {

				(my $slavehost,my $slaveport,my $slaveuser,my $slavepass)=routereq($request->{'device'});

				if ($slavehost) { 		# If this request is routable....
					$request->{'slavehost'} = $slavehost;
					$request->{'slaveuser'} = $slaveuser;
					$request->{'slaveport'} = $slaveport;
					$request->{'slavepass'} = $slavepass;

                			wlog("RUNQ : MASTER: Request: $request->{'rid'} Routable");    
					my $result=domaster($request);
                			wlog("RUNQ : MASTER: Request: $request->{'rid'} Result: $result->{'success'} Message: $result->{'message'}");    
					if ($result->{'success'} ) {
						$pcaps{$request->{'rid'}}=$request->{'filename'} ; # Report done
					} else {
						$pcaps{$request->{'rid'}}="ERROR" ; # Report FAIL 
					}
				} else {
					wlog("RUNQ : No ofpc-route to $request->{'device'}. Cant extract.");
					$pcaps{$request->{'rid'}}="NOROUTE"; # Report FAIL 
				}
			} else {
				my $result = doslave($request,$rid);
				if ($result->{'success'}) {
                			wlog("RUNQ : SLAVE: Request: $request->{'rid'} Success. File: $result->{'filename'} $result->{'size'} now cached on SLAVE in $config{'SAVEDIR'}"); 
					$pcaps{$request->{'rid'}}=$result->{'filename'};
				} else {
                			wlog("RUNQ: SLAVE: Request: $request->{'rid'} Result: Failed, $result->{'message'}.");    
				}
			}
        	}
	}
}

sub mkBPF($) {
        # Give me an event hash, and ill give you a bpf
	my $request=shift;
        my @eventbpf=();
        my $bpfstring;

        if ($request->{'proto'}) {
                $request->{'proto'} = lc $request->{'proto'}; # In case the tool provides a protocol in upper case
        }   

        if ( $request->{'sip'} xor $request->{'dip'} ) { # One sided bpf
                if ($request->{'sip'} ) { push(@eventbpf, "host $request->{'sip'}" ) } 
                if ($request->{'dip'} ) { push(@eventbpf, "host $request->{'dip'}" ) } 
        }   

        if ( $request->{'sip'} and $request->{'dip'} ) { 
                 push(@eventbpf, "host $request->{'sip'}" );
                 push(@eventbpf, "host $request->{'dip'}" );
        }   
   
        if ( $request->{'proto'} ) { 
                 push(@eventbpf, "$request->{'proto'}" );
	}
 
        if ( $request->{'spt'} xor $request->{'dpt'} ) { 
                if ($request->{'spt'} ) { push(@eventbpf, "port $request->{'spt'}" ) } 
                if ($request->{'dpt'} ) { push(@eventbpf, "port $request->{'dpt'}" ) } 
        }   

        if ( $request->{'spt'} and $request->{'dpt'} ) { 
                 push(@eventbpf, "port $request->{'spt'}" );
                 push(@eventbpf, "port $request->{'dpt'}" );
        }   

        # cat the eventbpf array into a string
        foreach (@eventbpf) {
                if ($bpfstring) { 
                        $bpfstring = $bpfstring . " and "; 
                } else {
                        $bpfstring = $_ ;
                        next;
                }   
                $bpfstring = $bpfstring . $_ . " ";
        }   
        return($bpfstring);
}


=head2 findBuffers
        Rather than search over ALL pcap files on a slave, if we know the timestamp(s) that we want to focus on,
	why no narrow down the search scope. Much more speedy extraction!!!!!

	Takes a timestamp and a number of files, returns an array of files.

=cut

sub findBuffers {

        my $targetTimeStamp=shift;
        my $numberOfFiles=shift;
        my @TARGET_PCAPS=();
        my %timeHash=();
        my @timestampArray=();
	my @pcaps;
	my $vdebug=0;	# Enable this to debug the pcap selection process
			# It's VERY verbose, so it's off even when debugging is enabled

	print "DEBUG: WARNING vdebug not enabled to inspect pcap filename selection\n" if ($debug and not $vdebug);

	my @pcaptemp = `ls -rt $config{'BUFFER_PATH'}/ofpc-$config{'NODENAME'}-pcap.*`;
        foreach(@pcaptemp) {
                chomp $_;
                push(@pcaps,$_);
        }

        print "DEBUG: $numberOfFiles requested each side of target timestamp \n" if ($debug);

        $targetTimeStamp=$targetTimeStamp-0.5;                  # Remove risk of TARGET conflict with file timestamp.   
        push(@timestampArray, $targetTimeStamp);                # Add target timestamp to an array of all file timestamps
        $timeHash{$targetTimeStamp} = "TARGET";                 # Method to identify our target timestamp in the hash

        foreach my $pcap (@pcaps) {
                (my $fileprefix, my $timestamp)  = split(/\./,$pcap);
                print " - Adding file $pcap with timestamp $timestamp (" . localtime($timestamp) . ") to hash of timestamps \n" if ($vdebug and $debug);
                $timeHash{$timestamp} = $pcap;
                push(@timestampArray,$timestamp);
        }

        my $location=0;
        my $count=0;
        if ($debug and $vdebug) {           			# Yes I do this twice, but it helps me debug timestamp pain!
                print "-----------------Array----------------\n";
                foreach (sort @timestampArray) {
                        print "DEBUG  $count";
                        print " - $_ $timeHash{$_}\n";
                        $count++;
                }
                print "-------------------------------------\n";
        }

        $location=0;
        $count=0;
        foreach (sort @timestampArray){                 # Sort our array of timetsamps (including
               $count++;                               # our target timestamp)
               print " + $count - $_ $timeHash{$_}\n" if ($debug and $vdebug);
               if ( "$timeHash{$_}" eq "TARGET" ) {
                        $location=$count - 1;
                        if ($debug and $vdebug) {
                                print "DEBUG: Got TARGET match of $_ in array location $count\n";
                                print "DEBUG: Pcap file at previous to TARGET is in location $location -> filename $timeHash{$timestampArray[$location]} \n";
                        }
                        last;
                } elsif ( "$_" == "$targetTimeStamp" ) {     # If the timestamp of the pcap file is identical to the timestamp
                        $location=$count;               # we are looking for (corner case), store its place
                        if ($debug and $vdebug) {
                                print " - Got TIMESTAMP match of $_ in array location $count\n";
                                print "   Pcap file associated with $_ is $timeHash{$timestampArray[$location]}\n";
                        }
                        last;
                }
        }

        if ($debug) {
                if (my $expectedts = ((stat($timeHash{$timestampArray[$location]}))[9])) {
                        my $lexpectedts = localtime($expectedts);
                        print " - Target PCAP filename is $timeHash{$timestampArray[$location]} : $lexpectedts\n" if ($debug and $vdebug);
                }
        }

        # Find what pcap files are eachway of target timestamp
        my $precount=$numberOfFiles;
        my $postcount=$numberOfFiles;
        unless ( $timeHash{$timestampArray[$location]} eq "TARGET" ) {
                push(@TARGET_PCAPS,$timeHash{$timestampArray[$location]});
        } else {
                print "DEBUG Skipping got target\n" if ($debug);
        }

        while($precount >= 1) {
                my $file=$location-$precount;
                if ($file < 0 ){        # I the range to search is out of bounds
                	print " - Eachway generated an OOB earch at location $file in array. Thats le 0!\n" if ($debug and $vdebug);
                } else {
                        if ($timeHash{$timestampArray[$file]}) {
                                unless ( "$timeHash{$timestampArray[$file]}" eq "TARGET" ) {
                                        push(@TARGET_PCAPS,$timeHash{$timestampArray[$file]});
                                }
                        }
                }
                $precount--;
        }
        while($postcount >= 1) {
                my $file=$location+$postcount;
                if ($file > (@timestampArray - 1) ) {       # I the range to search is out of bounds
                	print " - Eachway generated an OOB search at location $file in array. Skipping each way value too high \n" if ($debug and $vdebug);
                } else {
                        if ($timeHash{$timestampArray[$file]}) {
                                unless ( "$timeHash{$timestampArray[$file]}" eq "TARGET" ) {
                                        push(@TARGET_PCAPS,$timeHash{$timestampArray[$file]});
                                }
                        }
                }
                $postcount--;
        }
        return(@TARGET_PCAPS);
}

=head2 doExtract
	Performs an  "extraction" of session(s) from pacp(s) using tcpdump.
	Pass me a bpf, list of pcaps(ref), and a filename and it returns a filesize and a MD5 of the extracted file
	e.g.
	doExtract($bpf, \@array_of_files, $requested_filename);
	return($filename,$filesize,$md5);

	Note, doExtract also expected a few globals to exist.
		$tempdir
		$config{'TCPDUMP'}
		$confgi{'MERGECAP'}
		$debug
=cut

sub doExtract{
        my $bpf=shift;
	my $filelistref=shift;
	my $mergefile=shift;
	my @filelist=@{$filelistref};
	my $tempdir=tempdir(CLEANUP => 1);
	
        my @outputpcaps=();
        print "DEBUG: Doing Extraction with BPF $bpf into tempdir $tempdir\n" if ($debug);

        foreach (@filelist){
                (my $pcappath, my $pcapid)=split(/\./, $_);
                chomp $_;
                my $filename="$tempdir/$mergefile-$pcapid.pcap";
                push(@outputpcaps,$filename);
                my $exec="$config{'TCPDUMP'} -r $_ -w $filename $bpf > /dev/null 2>&1";
		print "DEBUG: Exec: $exec\n" if ($debug);
                `$exec`;
        }

        #Now that we have some pcaps, lets concatinate them into a single file
        unless ( -d "$tempdir" ) {
                die("Tempdir $tempdir not found!")
	}

        print " - Merge command is \"$config{'MERGECAP'} -w $config{'SAVEDIR'}/$mergefile  @outputpcaps\" \n" if ($debug);

        if (system("$config{'MERGECAP'} -w $config{'SAVEDIR'}/$mergefile @outputpcaps")) {
		return(0,0,0);
        }

	# Calculate a filesize (in human readable format), and a MD5
        my $filesize=`ls -lh $config{'SAVEDIR'}/$mergefile |awk '{print \$5}'`; 
        chomp $filesize;
	open(PCAPMD5, '<', "$config{'SAVEDIR'}/$mergefile") or die("cant open pcap file $config{'SAVEDIR'}/$mergefile to create MD5");
	my $md5=Digest::MD5->new->addfile(*PCAPMD5)->hexdigest;
	close(PCAPMD5);


	wlog("SLAVE: Extracted to $mergefile, $filesize, $md5\n");

        # Clean up temp files that have been merged...
	File::Temp::cleanup();

	return($mergefile,$filesize,$md5);
}

########### Start Here  ############
$SIG{PIPE} = \&pipeHandler;

# Some config defaults
$config{'NODENAME'} = "OPENFPC"; 
$config{'MASTER'}=0;		# Default is slave mode
$config{'SAVEDIR'}="/tmp";	# Where to save cached PCAP files.
$config{'LOGFILE'}="/tmp/ofpc-queued.log"; 	# Log file
$config{'OFPC_Q_PID'}="/tmp/ofpc-queued.pid";
$config{'TCPDUMP'} = "/usr/sbin/tcpdump";
$config{'MERGECAP'} = "/usr/bin/mergecap";

$SIG{"TERM"}  = sub { closedown("TERM") };
$SIG{"KILL"}  = sub { closedown("KILL") };

# Open and start syslog
openlog("OpenfpcQ","pid", "daemon");


GetOptions (    'c|conf=s' => \$CONFIG_FILE,
		'd|daemon' => \$daemon,
		'h|help' => \$help,
		'debug' => \$debug,
		'v|verbose' => \$verbose,
                );
if ($debug) { 
	$verbose=1;
	print "DEBUG = ON!\n"
}

if ($help) { 
	showhelp();
	exit;
}

wlog("CONF: Reading config file $CONFIG_FILE");

unless ($CONFIG_FILE) { die "Unable to find a config file. See help (--help)"; }
open my $config, '<', $CONFIG_FILE or die "Unable to open config file $CONFIG_FILE $!";
while(<$config>) {
        chomp;
        if ( $_ =~ m/^[a-zA-Z]/) {
                (my $key, my @value) = split /=/, $_;
                unless ($key eq "USER") {
                        $config{$key} = join '=', @value;
                } else {
                        wlog("CONF: Adding user \"$value[0]\" Pass \"$value[1]\"\n") if ($verbose);
                        $userlist{$value[0]} = $value[1] ;
                }
        }
}
close $config;

my $numofusers=keys (%userlist);
unless ($numofusers) {
	die "No users defined in config file.\n";
}

wlog("*********** OpenFPC $openfpcver **********");
wlog("**    http://www.openfpc.org    **");

if ($config{'MASTER'}) {
        wlog("CONF: Starting OFPC Node \"$config{'NODENAME'}\" as a MASTER");
	if ($config{'SLAVEROUTE'}) {
		open SLAVEROUTE, '<', $config{'SLAVEROUTE'} or die "Unable to open slave route file $config{'slaveroute'} $!";
		wlog("CONF: Reading route file $config{'SLAVEROUTE'}");
		while(<SLAVEROUTE>) {
			chomp $_;
			unless ($_ =~ /^[# \$\n]/) {
				if ( (my $key, my $value) = split /=/, $_ ) {
					$route{$key} = $value;	
					wlog("CONF: Adding route for $key as $value") if ($verbose);
				}
			}
		}
		close SLAVEROUTE;
	}
} else {
        wlog("CONF: Starting OFPC Node \"$config{'NODENAME'}\" as a SLAVE");
}

# Start listener
print "*  Starting listener on TCP:$config{'OFPC_PORT'}\n" if ($debug);
my $listenSocket = IO::Socket::INET->new(
                                LocalPort => $config{'OFPC_PORT'},
                                Proto => 'tcp',
                                Listen => '10',
                                Reuse => 1,
                                );

unless ($listenSocket) { die("Problem creating socket!"); }
$listenSocket->autoflush(1);

if ($daemon) {
	print "[*] OpenFPC Queued - Daemonizing\n";
	print " -  Leon Ward http://www.openfpc.org/\n";

	chdir '/' or die "Can't chdir to /: $!";
	umask 0;
	open STDIN, '/dev/null'   or die "Can't read /dev/null: $!";
	open (STDOUT, "> $config{'LOGFILE'}") or die "Can't open Log for STDOUT  $config{'LOGFILE'}: $!\n";
	defined(my $pid = fork)   or die "Can't fork: $!";
	if ($pid) {
		open (PID, "> $config{'OFPC_Q_PID'}") or die "Unable write to pid file $config{'OFPC_Q_PID'}: $!\n";
      		print PID $pid, "\n";
      		close (PID);
		exit 0;
	}
	# Redirect STDERR Last to catch any error in the fork() process.
	open (STDERR, "> $config{'LOGFILE'}") or die "Can't open Log for STDERR $config {'LOGFILE'}: $!\n";
	setsid or die "Can't start a new session: $!";
}

threads->create("runq");

while (my $sock = $listenSocket->accept) {
	# set client socket to non blocking
	my $nonblocking = 1;
	ioctl($sock, 0x8004667e, \\$nonblocking);
	$sock->autoflush(1);
	my $client_ip=$sock->peerhost;
	wlog("COMMS: Accepted new connection from $client_ip") ;

	# start new thread and listen on the socket
	threads->create("comms", $sock);
}
