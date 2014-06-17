package OFPC::Common;

#########################################################################################
# Copyright (C) 2013 Leon Ward 
# OFPC::Parse - Part of the OpenFPC - (Full Packet Capture) project
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
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use Exporter;
use Switch;
use OFPC::Config;
use OFPC::Common;
use OFPC::Request;
use Sys::Syslog;
use File::Temp(qw(tempdir));
use File::Basename;
use Digest::MD5(qw(md5_hex));
use Archive::Zip qw( :ERROR_CODES :CONSTANTS );
use threads::shared;
use Filesys::Df;
use Data::Dumper;
use JSON::PP;
our @ISA = qw(Exporter);
@EXPORT = qw(wlog);
@EXPORT_OK = qw(ALL);
$VERSION = '0.5';



=head2 initlog
    Set up any logging subsystems.
    We need to open up syslog, and maybe also log to a debug file somewhere

    Expects: nothing,
    Returns: 1 for success, 0 for error;
=cut

sub initlog{
    # Open and start syslog
    openlog("OpenfpcQ","pid", "daemon");    
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

=head2 getmd5
	Get the md5 for a file. 
	Takes: filename (including path)
	Returns: md5sum or 0 for fail.
        Leon - 2010
=cut

sub getmd5{
	my $file=shift;
	unless (open(MD5, '<', $file)) {
		wlog("MD5: ERROR: Cant open file $file to get MD5");
		return 0;
	}
	my $md5=Digest::MD5->new->addfile(*MD5)->hexdigest;
	wlog("MD5 : $file => $md5") if $debug;
	close(MD5);
	return($md5);
}

=head2 wlog
	Write the string passed to the function as a log
	e.g. wlog("Something just went down");
=cut
                        
sub wlog{
        my $msg =  shift;
        chomp $msg;
        my $gmtime=gmtime();
	my $logdata = "$config{'NODENAME'} " .  $msg;
        if ($daemon == 0) {
            print "$gmtime GMT: $logdata\n" ;
        }
	syslog("info",$logdata);
}

=head2 getrequestid
	Generate a "unique" request ID for the extraction request
	It's pretty basic right now, but it's here in case I want
	to make each rid unique over program restarts.
=cut

sub getrequestid{
	$mrid++;
        wlog("COMMS: Request ID is $mrid\n") if $debug;
	return($mrid);
}


sub checkbpf{
        my $bpf=shift;
        # Check BPF to ensure it's valid before doing anything with it.
        unless ($bpf =~/^[A-Za-z0-9 \.\[\]\(\)&=\/]+$/) {
                wlog("DEBUG: BPF Failed input validation, bad chars in $bpf");
                return(0);
        }
        # To check BPF is valid, open a pcap for reading.
        my @pcaptemp = `ls -rt $config{'BUFFER_PATH'}/openfpc-$config{'NODENAME'}.pcap.*`;
        if (@pcaptemp) {
                my $p=shift(@pcaptemp);
                chomp $p;
                my $i=system("$config{'TCPDUMP'} -nnr $p -c 1 \"$bpf or not($bpf)\" > /dev/null 2>&1");
                if ($i) {
                        wlog("WARN : BPF failed to validate - $bpf");
                        return(0);
                    }
                    # Looks like the BPF is okay then...
                    return(1);
        } else {
                wlog("WARN: No pcaps found in $config{'BUFFER_PATH'}");
                return(2);
        }
}

=head2 mkBPF
    Generate a BPF compatable filter string from the values found in an event hash.
    Takes: \%request
    Returns: $bpf
    
=cut
sub mkBPF($) {
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

=head2 getstatus
	Get the status of a node, or bunch of nodes if this is a proxy device
=cut

sub getstatus{
	my $request=shift;
	my $exec=0;
	my %sc = (
		nodename => 0,
		proxy => 0,
		success => 0,
		nodelist => [],
	);

	# Supported types for text format conversion are 
		# e = time epoch
		# t = text
		# b = binary
		# s = space (bytes)
		# p = %a

	my %s = (   
		success => {
			val => 0,
			text => "Request Status                 ",
			type => "t",
		},

		ofpctype => {
			val => 0,
			text => "Node Type                      ",
			type => "t",
		},
		nodename => {
			val => 0,
			text => "Node Name                      ",
			type => "t",
		},
		firstpacket => {
			val => 0,
			text => "Oldest packet in storage       ",
			type => "e",
		},
		packetpacptotal => {
			val => 0,
			text => "PCAP file space used           ",
			type => "t",
		},
		packetspace => {
			val => 0,
			text => "Packet storage utilization     ",
			type => "p",
		},
		packetused => {
			val => 0,
			text => "Packet storage used            ",
			type => "b",
		},
		sessionspace => {
			val => 0,		
			text => "Session storage utilization    ",
			type => "p",
		},
		sessionused => {
			val => 0,
			text => "Session storage used           ",
			type => "b",
		},
		sessioncount => {
			val => 0,
			text => "Number of sessions in Database ",
			type => "t",
		},
		sessionlag => {
			val => 0,
			text => "Number of session files lagging",
			type => "t",
		},
		savespace => {
			val => 0,
			text => "Space available in save path   ",
			type => "p",
		},
		saveused => {
			val => 0,
			text => "Space used in the save path    ",
			type => "b",
		},
		comms => {
			val => 0,
			text => "Communication with nodes       ",		
			type => "t",
		},
		ld1 => {
			val => 0,
			text => "Load Average 1                 ",
			type => "t",
		},
		ld5 => {
			val => 0,
			text => "Load average 5                 ",
			type => "t",
		},
		ld15 => { 
			val => 0,
			text => "Load average 15                ",
			type => "t",
		},
		message => { 
			val => 0,
			text => "Message                        ",
			type => "t",
		},			# Message for error text
		firstctx => {
			val => 0,
			text => "Oldest session in storage      ",
			type => "e",
		},
	);

	unless ($config{'PROXY'}) { 	# Process as a node. Don't check proxy specific stuff like comms
		$s{'ofpctype'}{'val'} = "NODE";
		$s{'nodename'}{'val'} = $config{'NODENAME'};
		# Get timestamp of oldest pcap buffer
		unless (opendir(DIR,$config{'BUFFER_PATH'}) ) {
			$s{'message'}{'val'} = "Unable to open buffer path $config{'BUFFER_PATH'}";
			return \%s;
		} 
		my @files=readdir(DIR);
		unless (@files) {
			$s{'message'}{'val'}= "Unable to open buffer path $config{'BUFFER_PATH'}";
			return \%s;
		}
		@files=sort(@files);

		# A sorted dir could also include other files. We can apply a check for the daemonlogger prfix
		# to make sure we don't end up with some other crap, or ".",".." etc

		my $oldestfile=0;
		foreach (@files) {
			if ($_  =~ /$config{'NODENAME'}\.pcap/) {
				$oldestfile=$_;
				wlog("DEBUG: Oldest PCAP file is $oldestfile") if $debug;
				last;
			}
		}

		if ( $oldestfile =~ /$config{'NODENAME'}\.pcap\.([0-9]+)/ ) {
			$s{'firstpacket'}{'val'} = $1;
		}

		# Get disk space info
		##############################
		my $packetref=df("$config{'BUFFER_PATH'}");
		$s{'packetspace'}{'val'} = $packetref->{'per'};
		$s{'packetused'}{'val'} = $packetref->{'used'};
		wlog("DEBUG: Packet used is $packetref->{'used'} \n") if $debug;

		if ($config{'ENABLE_SESSION'}) {
			my $sessionref=df("$config{'SESSION_DIR'}");
			$s{'sessionspace'}{'val'} = $sessionref->{'per'};
			$s{'sessionused'}{'val'} = $sessionref->{'used'};
		} else {
			$s{'sessionspace'}{'val'} = "Disabled";
			$s{'sessionused'}{'val'} = "Disabled";
		}

		# Get summary of pcap file total space in this buffer
		################################
		my $ps=`du -hsc $config{'BUFFER_PATH'}/openfpc-$config{'NODENAME'}\.pcap* |grep total`;
		(my $pso)=split(/\s/,$ps);
		wlog ("pso is '$pso'") if $debug;
		$s{'packetpacptotal'}{'val'} = $pso;

		my $saveref=df("$config{'SAVEDIR'}");
		$s{'savespace'}{'val'} = $saveref->{'per'};
		$s{'saveused'}{'val'} = $saveref->{'used'};
		wlog("DEBUG: Savespace in $config{'SAVEDIR'} is $s{'savespace'}{'val'} \n") if $debug;
	
		# Grab uptime and load average data
		####################################	
		my $uptime=`uptime`;
		chomp $uptime;
		if ($uptime =~ /load average.*:\s*([0-9]\.[0-9]+),*\s*([0-9]\.[0-9]+),*\s*([0-9]\.[0-9]+)/){ 
			$s{'ld1'}{'val'} = $1;
			$s{'ld5'}{'val'} = $2;
			$s{'ld15'}{'val'} = $3;
		}

		# Get session DB data
		#################################
		if ($config{'ENABLE_SESSION'}) {
			wlog("DEBUG: Session data enabled on this node. Checking DB status") if $debug;
			if ( my $dbh= DBI->connect("dbi:mysql:database=$config{'SESSION_DB_NAME'};host=localhost",$config{'SESSION_DB_USER'},$config{'SESSION_DB_PASS'}) ) {
			    
			    # Get count of sessions in DB
			    my $sth= $dbh->prepare("SELECT COUNT(*) FROM session") or wlog("STATUS: ERROR: Unable to get session table size $DBI::errstr");
			    if ( $sth->execute() ) {
			        while ( my @row = $sth->fetchrow_array ) {
			        	$s{'sessioncount'}{'val'} = $row[0];
					}
			    } else {
				    wlog("STATUS: ERROR: Unable to exec SQL command");
			    }
			    wlog("DEBUG: Session DB count is $s{'sessioncount'}{'val'}\n") if $debug;

			    # Get Oldest session time
			    $sth= $dbh->prepare("SELECT unix_timestamp(start_time) FROM session ORDER BY start_time LIMIT 1") or wlog("STATUS: ERROR: Unable to get first conenction $DBI::errstr");
			    $sth->execute() or wlog("STATUS: ERROR: Unable to exec SQL command");
			    while ( my @row = $sth->fetchrow_array ) {
  				$s{'firstctx'}{'val'} = $row[0];
			    }
			    wlog("DEBUG: Oldest connection in session DB is $s{'firstctx'}{'val'}\n") if $debug;

			    $dbh->disconnect or wlog("Unable to disconnect from DB $DBI::errstr");
			    if (opendir(SESSION_DIR,$config{'SESSION_DIR'}) ) { 
				while (my $filename=readdir(SESSION_DIR)) {
				      	$s{'sessionlag'}{'val'}++ unless $filename =~ /^(\.|failed)/;
			        }
			    }
			} else {
				wlog("DEBUG: Unable to connect to DB for stats info");
			}
		} else {
			wlog("DEBUG: Session data disabled on this node");
		}

		# Check we are providing back some valid data
		if ( $s{'ld1'}{'val'} and $s{'nodename'}{'val'} ) {
			$s{'success'}{'val'} = 1; 	
		}

	} else {
		wlog("Recieved PROXY STATUS request - Not implemented");
		$s{'message'}{'val'} = "Proxy status not implemented yet";
		$s{'ofpctype'}{'val'} = "PROXY";
	}

	# Put the node status hash into a container that can scale for multiple nodes

	$sc{'nodename'} = $config{'NODENAME'};
	push (@{$sc{'nodelist'}},$config{'NODENAME'});
	$sc{'success'} = $s{'success'};
	$sc{$config{'NODENAME'}} = \%s;

	return(\%sc);
}

=head2 trimsessiondb
	The Session DB doesn't have a need to be larger than the oldest packet.
=cut

sub trimsessiondb(){

	my $trimtime=0;		# New value of oldest ctx
	my $status=OFPC::Common::getstatus();

	my $fc=$status->{$config{'NODENAME'}}{'firstctx'}{'val'};
	my $fp=$status->{$config{'NODENAME'}}{'firstpacket'}{'val'};

	wlog("TRIM: Trimming Session DB from: $fc (" . localtime($fc) . ") to $fp (". localtime($fp) . ")") if $debug;

	my $dbh= DBI->connect("dbi:mysql:database=$config{'SESSION_DB_NAME'};host=localhost",$config{'SESSION_DB_USER'},$config{'SESSION_DB_PASS'}) 
		or wlog("DEBUG: Unable to connect to DB");

	my $sth= $dbh->prepare("DELETE FROM session WHERE unix_timestamp(start_time) < $fp") 
		or wlog("STATUS: ERROR: Unable to prep query $DBI::errstr");

	if ($sth->execute()) {
		$trimtime=$fp;
	} else {
		 wlog("STATUS: ERROR: Unable to trim session DB");
	}

	$dbh->disconnect or wlog("Unable to disconnect from DB $DBI::errstr");
	return($trimtime);
}


=head2 backgroundtasks
	Perform regular tasks every X seconds.
        
	Tasks Include:
            - Clean up CTX table (trim to oldest packet).
        Takes:   $seconds (count of how many seconds to sleep for)
	Returns: nothing (loops forever)
=cut

sub backgroundtasks($){
    my $time=$config{'TASK_INTERVAL'};
    my $mintime=59;
    if ($time >= $mintime) {     # Check time is a reasonable value
        wlog("TASKS: Sleeping $time seconds for each task interval") if $debug;
	while(1) {
            sleep $time;
            # Trim session table to the oldest packet in the PCAP buffer
            if ($config{'PROXY'}) {
                wlog("TASKS: Woke up to run PROXY tasks...") if ($debug);
            } else {
                wlog("TASKS: Woke up to run NODE tasks...") if ($debug);
		if ($config{'ENABLE_SESSION'}) {
                	my $trim=trimsessiondb;
                	wlog("TASKS: Session DB trimmed to $trim") if ($debug);
		} else {
                	wlog("TASKS: Wont trim session DB, session not enabled") if ($debug);
		}
            }
	}
    } else {
	wlog("TASK: ERROR: Not starting periodic tasks, time value $time seconds is less than minimum value of $mintime seconds");
    }
}

=head2 decoderequest
	Take the OFPC request JSON, and provide a hash(ref) to the decoded data.
	Example of a OFPC request:
	ofpc||fetch||||/tmp/foo.pcap||||auto||ofpc-v1 type:event sip:192.168.222.1 dip:192.168.222.130 dpt:22 proto:tcp time:1274864808 msg:Some freeform text||Some comment text
	ofpc||summary||||||||||||||top_sip_by_volume
=cut

sub decoderequest($){
	my $now=time();
	my $rj=shift;
    my $rawrequest=$rj;
    my %request=(   
    	user     	=>  0,
        action   	=>  0,
		rid	 		=>	0,
        device   	=>  0,
        filename 	=>  0,
		tempfile 	=>	0,
        filetype 	=>  0,
        logtype  	=>  0,
        logline  	=>  0,
		sip			=>	0,
		dip			=>	0,
		proto		=>	0,
		spt			=>	0,
		dpt			=>	0,
		msg			=>	0,
		bpf     	=>	0,
		rtime		=>	0,
		timestamp 	=>	0,
		stime		=>	0,
		etime		=>	0,
		comment 	=>	0,
		valid   	=>	0,
		sumtype 	=>	0,
		msg 		=> 0,
		limit 		=> 0,
	);
    my @requestarray = split(/\|\|/, $rawrequest);
    my $argnum=@requestarray;

	$request{'rtime'} = gmtime();

    my $r;
    unless ($r=decode_json($rj)) {	
    	wlog("ERROR: Failed to decode request JSON");
    	$request{'msg'} = "Bad request. Unable to parse JSON.";
    	return(\%request);
    } 
	# Copy values from the client JSON request into the server request hash.
	
	$request{'user'}		=	$r->{'user'}{'val'};
	$request{'action'}		=	$r->{'action'}{'val'}; 			# Action (store,status,fetch,summary,etc)
	$request{'device'} 		=	$r->{'device'}{'val'};			# Device to request from i.e openfpc-node
	$request{'filename'} 	= 	$r->{'filename'}{'val'};		# Filename to save file as 
	$request{'filetype'} 	= 	$r->{'filetype'}{'val'};		# Filetype zip or pcap?
	$request{'logtype'} 	= 	$r->{'logtype'}{'val'};			# Type of log being processed
	$request{'logline'}		= 	$r->{'logline'}{'val'};			# The log-line (including one made from session identifiers
	$request{'comment'} 	= 	$r->{'comment'}{'val'};			# User comments
	$request{'sumtype'}		= 	$r->{'sumtype'}{'val'}; 		# Type of connection summary
	$request{'limit'}		= 	$r->{'limit'}{'val'}; 		# Type of connection summary

	$request{'action'} = lc $request{'action'};
	wlog("DECOD: Recieved action $request{'action'}") if ($debug);

	if ($request{'action'} =~ /(fetch|store)/) {

		# Data could be requested in multiple forms, need to define a priority order in case multiple appear in the same request
		# bpf
		# session identifiers
		# logline

		if ($r->{'bpf'}{'val'}) {
                        wlog("DEBUG: Found BPF set as $r->{'bpf'}{'val'}\n") if $debug;
                        # Check BPF to ensure it's valid before doing anything with it.
                        my $bpfcheck = checkbpf($r->{'bpf'}{'val'});
                        if ($bpfcheck==1) {
                                $request{'bpf'} = $r->{'bpf'}{'val'};
                                $request{'timestamp'} = $r->{'timestamp'}{'val'};
                                $request{'stime'} = $r->{'stime'}{'val'};
                                $request{'etime'} = $r->{'etime'}{'val'};
                        } elsif ($bpfcheck==2) {
                                $request{'msg'} = "No pcap files found in buffer path";
                                return(\%request);
                        } else {
                                $request{'msg'} = "BPF Failed input validation";
                                return(\%request);
                        }
		} elsif ($r->{'logline'}{'val'}) {
			wlog("DEBUG: Found logline requested as $r->{'logline'}{'val'}\n") if $debug;

			# Check logline is valid
			my ($eventdata)=OFPC::Parse::parselog($request{'logline'});

			unless ($eventdata->{'parsed'}) {
				wlog("ERROR: Cannot parse logline");
				$request{'msg'} = "Unable to parse logline \"$request{'logline'}\"";
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
				wlog("DEBUG: logline timestamp has been set to $request{'timestamp'}\n");
			}
		} else {
			wlog("DEBUG: No BPF or logline detected, using session identifiers if set") if $debug;
			$request{'sip'} = $r->{'sip'}{'val'};
			$request{'dip'} = $r->{'dip'}{'val'};
			$request{'spt'} = $r->{'spt'}{'val'};
			$request{'dpt'} = $r->{'dpt'}{'val'};
			$request{'timestamp'} = $r->{'timestamp'}{'val'};
			$request{'stime'} = $r->{'stime'}{'val'};
			$request{'etime'} = $r->{'etime'}{'val'};
			$request{'proto'} = $r->{'proto'}{'val'};
			wlog("DEBUG: Timestamp is $r->{'timestamp'}{'val'}") if $debug;
			wlog("DEBUG: Session IDs sip: \'$r->{'sip'}{'val'}\' dip: \'$r->{'dip'}{'val'}\' spt: \'$r->{'spt'}{'val'}\' dpt: \'$r->{'dpt'}{'val'}\' proto: \'$r->{'proto'}{'val'}\'") if $debug;

		}

		# Default to PCAP file if filetype not specified
		unless ($request{'filetype'}) {
			$request{'filetype'} = "PCAP";
		}

		wlog("DECOD: User $request{'user'} assigned RID: $request{'rid'} for action $request{'action'}. Comment: $request{'comment'} Filetype : $request{'filetype'}");
		$request{'valid'} = 1;

	} elsif ($request{'action'} =~ /(status|summary)/) {
		wlog("DECOD: Summary or Status request") if ($debug);
		$request{'stime'} = $r->{'stime'}{'val'};
		$request{'etime'} = $r->{'etime'}{'val'};
		$request{'valid'} = 1;
	} elsif ($request{'action'} =~/search/) {
		wlog("DECOD: Search request") if ($debug);
		$request{'sip'} = $r->{'sip'}{'val'};
		$request{'dip'} = $r->{'dip'}{'val'};
		$request{'spt'} = $r->{'spt'}{'val'};
		$request{'dpt'} = $r->{'dpt'}{'val'};
		$request{'timestamp'} = $r->{'timestamp'}{'val'};
		$request{'stime'} = $r->{'stime'}{'val'};
		$request{'etime'} = $r->{'etime'}{'val'};
		$request{'proto'} = $r->{'proto'}{'val'};
		$request{'valid'} = 1;
	} else {
		# Invalid action
		wlog("DECOD: Received invalid action $request{'action'}");
		$request{'msg'} = "received invalid action $request{'action'}";
	}

	unless ($request{'comment'}) {
		$request{'comment'} = "No comment";
	}

	# If no timestamp, stime or etime have been specified, set a default range to search
	unless ($r->{'timestamp'}{'val'}) {
		if ($r->{'stime'}{'val'} and $r->{'etime'}{'val'}) {
			wlog("DECOD: stime and etime are set\n") if $debug;
		} else {
			wlog("DECOD: Neither timestamp or stime/etime are set, setting timestamp to $now, it was $r->{'timestamp'}{'val'}\n") if $debug;
			$request{'timestamp'} = $now;
		}
	}

	$request{'rid'} = OFPC::Common::getrequestid;
    return(\%request);
}


=head2 prepfile 
	prepare a file to deliver back to the client.
            
	Call with:
		\$request
	This consists of:
		- Checking if we are to queue it up for later or do it now
		- If this device is an openfpc-proxy -Check the routing to see if we need to fragment it and re-insert for each openfpc-node
		- Call the extract functions (if we are to do it now)
                - Prep the files (zip, get md5, size data etc)
		- Return a hashref containing
                
		( success => 0,
		  filename => 0,
		  message => 0,
		  filetype => 0,
		  md5 => 0,
		  size => 0,
		)

		success 1 = Okay 0 = Fail
		filename = Name of file (no path!)
		message = Error message
		filetype "PCAP" = pcap file "ZIP" = zip file
=cut

sub prepfile{
    my $request=shift;
    my @nodefiles=();		# List of files to zip up
    my $multifile=0;
    my $meta=0;
    my $rid=0;
    my %prep=(                  # Info about the preped file we can return
        success => 0,
        filename => 0,
        message => 0,
        filetype => "PCAP",
        md5 => 0,
        size => 0,
    );	

    # If a specific filetype is requested, set prep to gather it 
    if ($request->{'filetype'} eq "ZIP") {
        $multifile=1;
        $prep{'filetype'} = "ZIP";		
    }

    # If we are an openfpc-proxy, check if we need to frag this req into smaller ones, and get the data back from each node
    # If we are node, do the node action now (rather than enqueue if we were in STORE mode)
    # Check if we want to include the meta-text
    # Return the filename of the data that is to be sent back to the client.

    if ( $config{'PROXY'} ) {
		# Check if we can route this request

 		(my $nodehost,my $nodeport,my $nodeuser,my $nodepass)=routereq($request->{'device'});
		unless ($nodehost) { 	# If request isn't routeable....
			# Request from all devices
            wlog("PREP : Request is NOT routable. Requesting from all nodes SOUTH from this proxy");
	    	$multifile=1;	# Fraged request will be a multi-file return so we use a ZIP to combine
	    	foreach (keys %route) {
 				($nodehost,$nodeport,$nodeuser,$nodepass)=routereq($_);
				$request->{'nodehost'} = $nodehost;
				$request->{'nodeuser'} = $nodeuser;
				$request->{'nodeport'} = $nodeport;
				$request->{'nodepass'} = $nodepass;
                
				my $result=doproxy($request);
				if ($result->{'success'}) {
                    wlog("DEBUG: Adding $result->{'filename'} to zip list") if ($debug);
                    push (@nodefiles, $result->{'filename'});
				} else {
                    $prep{'message'} = $result->{'message'};
                    wlog("Error: $result->{'message'}");
				}
            }
		} else { 					# Route-able, do the proxy action 
        	$request->{'nodehost'} = $nodehost;
        	$request->{'nodeuser'} = $nodeuser;
        	$request->{'nodeport'} = $nodeport;
        	$request->{'nodepass'} = $nodepass;
			wlog("PREP: DEBUG: Taking proxy action on this request\n") if $debug;            
        	my $result=doproxy($request);

        	if ($result->{'success'}) {
				$prep{'success'} = 1;
				$prep{'md5'} = $result->{'md5'};
				$prep{'filetype'} = "PCAP";
				$prep{'filename'}="$result->{'filename'}";
       			push (@nodefiles, $result->{'filename'});
				wlog("PREP : Added $result->{'filename'} to zip list") if ($debug);
        	} else {
				$prep{'message'} = $result->{'message'};
				wlog("Error: $result->{'message'}");
        	}
		}
        
		# If we are sending back a zip, add the report file
		if ($prep{'filetype'} eq "ZIP") {
        	push (@nodefiles,"$request->{'filename'}.txt");
   		}

    } else { 	
		#####################################
		# Node stuff
		# Do node stuff, no routing etc just extract the data and make a report

		my $result = donode($request,$rid);

		if ($result->{'success'}) {
            $prep{'success'} = 1;
	    	$prep{'filename'} = $result->{'filename'};
	    	$prep{'md5'} = $result->{'md5'};
	    	$prep{'size'} = $result->{'size'};
		} else {
	    	$prep{'message'} = $result->{'message'};
		}
        
		my $reportfilename=mkreport(0,$request,\%prep);
        
		if ($prep{'filetype'} eq "ZIP") {
            if ($reportfilename) {
		push(@nodefiles,"$result->{'filename'}.txt");
            }
		}
		push(@nodefiles,$request->{'tempfile'});
    }
    
    # Now we have the file(s) we want to rtn to the client, lets zip or merge into a single pcap as requested
    if ($multifile) {
		if ( $prep{'filetype'} eq "PCAP" ) {
            # @nodefiles is a list of pcaps w/o a path, we need then with a path to merge
            # @mergefiles is a temp array of just that.
            my @mergefiles=();
            
            foreach (@nodefiles) {
				push(@mergefiles, "$config{'SAVEDIR'}/$_");
            }
            
            my $mergecmd="$config{'MERGECAP'} -w $config{'SAVEDIR'}/$request->{'tempfile'}.pcap @mergefiles";
            wlog("DEBUG: Merge cmd is $mergecmd\n") if $debug;
            if (@mergefiles) {
                unless (system($mergecmd)) {
                    wlog("DEBUG: Created $config{'SAVEDIR'}/$request->{'tempfile'}.pcap") if $debug;	
                    $prep{'filename'}="$request->{'tempfile'}.pcap";
                    $prep{'success'} = 1;
                    $prep{'md5'} = getmd5("$config{'SAVEDIR'}/$prep{'filename'}");
                } else {
                    wlog("PREP: ERROR merging $config{'SAVEDIR'}/$request->{'tempfile'}.pcap");	
                    $prep{'message'} = "PREP : Unable to proxy-merge!";
                }
            } else {
                wlog("ERROR: No files in merge queue. Did we get anything back from the client?");
                $prep{'message'} = "ERROR: No pcap files returned from any NODE";
            }
				
		} else {
            my $zip = Archive::Zip->new();
          	wlog("DEBUG: Prepping a ZIP file") if $debug; 
            foreach my $filename (@nodefiles) {
                if ( -f "$config{'SAVEDIR'}/$filename" ) {
                    $zip->addFile("$config{'SAVEDIR'}/$filename","$filename");
				} else {
                    wlog("ZIP : Cant find $config{'SAVEDIR'}/$filename to add to zip! - Skipping"); 
				}
            }
            
            if ($zip->writeToFileNamed("$config{'SAVEDIR'}/$request->{'tempfile'}.zip") !=AZ_OK ) {
				wlog("PREP: ERROR: Problem creating $config{'SAVEDIR'}/$request->{'tempfile'}.zip");
            } else {
				wlog("PREP: Created $config{'SAVEDIR'}/$request->{'tempfile'}.zip") if $debug;
				$prep{'filename'}="$request->{'tempfile'}.zip";
				$prep{'success'} = 1;
				$prep{'md5'} = getmd5("$config{'SAVEDIR'}/$prep{'filename'}");
                
                unless ($config{'KEEPFILES'}) {
                    wlog("DEBUG: Cleaning zip contents..\n") if ($debug);
					foreach (@nodefiles) {
                        wlog("DEBUG: Unlinking $config{'SAVEDIR'}/$_\n") if ($debug);
                        if ( -f "$config{'SAVEDIR'}/$_" ) {
							unlink("$config{'SAVEDIR'}/$_") or wlog("Cant unlink $config{'SAVEDIR'}/$_");
			    		}
					}
				}
            }
		}	
    }	

    return(\%prep);
}

=head2 donode
	It takes a decoded request as it's input, and returns a filename when the extraction has been done.
        
	A node action is one that will be processed on this device.
	It will perform the action itself rather than pass it on to another device.
	
	Returns a hash of
        
            success => 0,
            filename => 0,
            md5 => 0,
            size => 0,
            message => 0,
            
=cut

sub donode{
	my $extractcmd;
	my $request=shift;
	my @cmdargs=();
	my $bpf;
	my %result=( filename => 0,
            success => 0,
            message => 0,
            md5 => 0,
            size => 0,
	);

	wlog "DEBUG: Doing Node action \n" if $debug;
	# Unless we have been given a real bpf from the user, make our own
	unless ($request->{'bpf'} ) {
            $bpf=OFPC::Common::mkBPF($request);
	} else {
            $bpf=$request->{'bpf'};
	}
        
        # If for some reason we have failed to get a BPF, lets return an error
	unless ($bpf) {
            wlog("NODE : Request: $request->{'rid'} Insufficient constraints for request (Null BPF)");
            $result{'message'} = "Insufficient constraints for request (Null BPF)";
            return(\%result);
	}
        
	wlog("NODE : Request: $request->{'rid'} User: $request->{'user'} Action: $request->{'action'} BPF: $bpf");
        
	# Do we have a single timestamp or pair of them?
	# Single= event sometime in the middle of a session
	# stime/etime = a search time window to look for data over
       
	my @pcaproster=();
	if ( $request->{'stime'} and $request->{'etime'} ) {
            @pcaproster=bufferRange($request->{'stime'}, $request->{'etime'});
	} else  {
            # Event, single look over roster
            @pcaproster=findBuffers($request->{'timestamp'}, 2);
	}
        
	# If we don't get any pcap files, there is no point in doExtract
	my $pcapcount=@pcaproster;
	unless ($pcapcount) {
            $result{'message'} = "No suitable pcap files found in $config{'BUFFER_PATH'}";
            return(\%result);
	}
        
	wlog("DEBUG: PCAP roster ($pcapcount files in total) for extract is: @pcaproster\n") if $debug;
        
	(my $filename, my $size, my $md5) = doExtract($bpf,\@pcaproster,$request->{'tempfile'});
        
	if ($filename) {
            $result{'filename'} = $filename;
            $result{'success'} = 1;
	    $result{'message'} = "Success";
	    $result{'md5'} = $md5;
	    $result{'size'} = $size;
	    wlog("NODE : Request: $request->{'rid'} User: $request->{'user'} Result: $filename, $size, $md5");   
	} else {
            wlog("NODE : Request: $request->{'rid'} User: $request->{'user'} Result: Problem performing doExtract $filename, $size, $md5");   
	}
	
	# Create extraction Metadata file
	
	unless ( open METADATA , '>', "$config{'SAVEDIR'}/$filename.txt" ) { 
            wlog("PREP: ERROR: Unable to open MetaFile $config{'SAVEDIR'}/$request->{'tempfile'}.txt for writing");
            $result{'message'} = "Unable to open Metadata file  $config{'SAVEDIR'}/$request->{'tempfile'}.txt for writing";
            return(\%result);
	}
        
	print METADATA "Extract Report - OpenFPC Node action\n";
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

=head routereq
	Find device to make request from, and calculate the correct user/pass
	Expects $device
	returns $nodehost,$nodeport,$salveuser,$nodepass
=cut

sub routereq{
    my $device=shift;
    my $nodehost=0;
    my $nodeport=0;
    my $nodeuser=0;
    my $nodepass=0;
    my $nodevalue=0;
    if (exists $route{$device} ) {
        $nodevalue=$route{$device};
        ($nodehost, $nodeport, $nodeuser, $nodepass) = split(/:/, $nodevalue);
        wlog("ROUTE: Routing equest to node: $device ( $nodehost : $nodeport User: $nodeuser )");
    } else {
        wlog("ROUTE: No openfpc-route entry found for $device in routing table\n");
        return(0,0,0,0);
    }
        
    unless ($nodehost and $nodeport and $nodepass and $nodeuser) {
        wlog("ROUTE: ERROR: Unable to pass route line $nodevalue");
        return(0,0,0,0);		
    } else {
        return($nodehost,$nodeport,$nodeuser,$nodepass);
    }
}

=head2 getBufferInfo
	Get info about the traffic buffer.
	Takes no args,
	Returns a hash of buffer info.
=cut

sub getBufferInfo{
	my %info=(
		path => 0,
		firstfilename => 0,
		firsttimestamp => 0,
		lastfilename => 0,
		lasttimestamp => 0,
		fileprefix => 0,
	);
	my $splitstring="$config{'NODENAME'}\.pcap\.";

	opendir(DIR,$config{'BUFFER_PATH'}) or wlog("ERROR: Cant open buffer_path");

	my @files=readdir(DIR);
	@files=reverse sort(@files);
	$info{'firstfilename'} = shift(@files);
	$info{'lastfilename'} = $files[-1];
        ($info{'fileprefix'}, $info{'firsttimestamp'})  = split(/$splitstring/,$info{'firstfilename'});
        ($info{'fileprefix'}, $info{'lasttimestamp'})  = split(/$splitstring/,$info{'lastfilename'});

	return(\%info);
}

=head2 bufferRange
	Find out what pcap files contain the data between a start/end filename.
        This of course expects the filenames to be in the format created by
        daemonlogger.
        filename.pcap.$epoch
        
	Takes: $startfilename, $endfilename
        Returns: @files
=cut


sub bufferRange {
	my $starttimestamp=shift;
	my $endtimestamp=shift;
	my $include=0;
	my @pcaps=();
	my $startfile=0;
	my $endfile=0;
	my $bufferinfo=OFPC::Common::getBufferInfo();

	wlog("DEBUG: Buffer Range mode") if $debug;

	# Find first and last files/timestamps in case we are performing an out-of-bounds search
	my @starttmp=findBuffers($starttimestamp,0);
	if (defined $starttmp[0] ) {
		$startfile=$starttmp[0];
	} else {
		wlog("DEBUG: Startfile to early for buffer range. Using first file $bufferinfo->{'firstfilename'}\n");
		$startfile=$bufferinfo->{'firstfilename'};
	}
        
	my @endtmp=findBuffers($endtimestamp,0);
	if (defined $endtmp[0] ) {
		$endfile=$endtmp[0];
	} else {
		wlog("DEBUG: Endfile to late for buffer range. Using last file $bufferinfo->{'lastfilename'}\n");
		$endfile=$bufferinfo->{'lastfilename'};
	}
	wlog("Starting serach in $startfile ($starttimestamp)\n") if ($vdebug);
	wlog("Ending   search in $endfile ($endtimestamp)\n") if ($vdebug);
	# Look for files between startfile and endfile if startfile is not the same as endfile
        
	my @pcaptemp = `ls -rt $config{'BUFFER_PATH'}/openfpc-$config{'NODENAME'}.pcap.*`;
        
	unless ($startfile eq $endfile) {
        	foreach(@pcaptemp) {
	                chomp $_;
			if ($_ =~ /$startfile/) {
				$include=1;
			} elsif ($_ =~ /$endfile/ ) {
				$include=0;
			}
	       	        push(@pcaps,$_) if ($include);
			if ($vdebug) {
				wlog("VDBEUG: Including $_ \n") if ($include);
				wlog("VDEBUG: NOT include $_ \n") unless ($include);
			}
		}
        } else {
		# Add this single file to the @pcaps array
		push(@pcaps,$startfile);	
	}
	return(@pcaps);
}

=head2 findBuffers
        Rather than search over ALL pcap files on a node, if we know the timestamp(s) that we want to focus on,
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

	wlog("DEBUG: WARNING vdebug not enabled to inspect pcap filename selection\n") if ($debug and not $vdebug);

	my @pcaptemp = `ls -rt $config{'BUFFER_PATH'}/openfpc-$config{'NODENAME'}.pcap.*`;
        foreach(@pcaptemp) {
                chomp $_;
                push(@pcaps,$_);
        }

        wlog("DEBUG: Request is to look in $numberOfFiles files each side of target timestamp ($targetTimeStamp) ( " . localtime($targetTimeStamp) . ")\n") if $debug;

        $targetTimeStamp=$targetTimeStamp-0.5;                  # Remove risk of TARGET conflict with file timestamp.   
        push(@timestampArray, $targetTimeStamp);                # Add target timestamp to an array of all file timestamps
        $timeHash{$targetTimeStamp} = "TARGET";                 # Method to identify our target timestamp in the hash

        foreach my $pcap (@pcaps) {
		my $splitstring="$config{'NODENAME'}\.pcap\.";
                (my $fileprefix, my $timestamp)  = split(/$splitstring/,$pcap);
                print " - Adding file $pcap with timestamp $timestamp (" . localtime($timestamp) . ") to hash of timestamps \n" if $vdebug;
                $timeHash{$timestamp} = $pcap;
                push(@timestampArray,$timestamp);
        }

        my $location=0;
        my $count=0;
        if ($vdebug) {           			# Yes I do this twice, but it helps me debug timestamp pain!
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
                        if ($vdebug) {
                                wlog("DEBUG: Got TARGET match of $_ in array location $count\n"); 
                                wlog("DEBUG: Pcap file at previous to TARGET is in location $location -> filename $timeHash{$timestampArray[$location]} \n");
                        }
                        last;
                } elsif ( "$_" == "$targetTimeStamp" ) {     # If the timestamp of the pcap file is identical to the timestamp
                        $location=$count;               # we are looking for (corner case), store its place
                        if ($vdebug) {
                                print " - Got TIMESTAMP match of $_ in array location $count\n";
                                print "   Pcap file associated with $_ is $timeHash{$timestampArray[$location]}\n";
                        }
                        last;
                }
        }

        if ($vdebug) {
		my @tmptarget=split(/\./, $timeHash{$timestampArray[$location]});
		my $tts=pop(@tmptarget);
              #  wlog(" - Target PCAP filename is $timeHash{$timestampArray[$location]} : $tts ( " . localtime($tts) . ")\n");
                wlog(" - Target PCAP filename is $timeHash{$timestampArray[$location]} : $tts ( " . localtime($tts) . ")\n") if $tts;
        }

        # Find what pcap files are eachway of target timestamp
        my $precount=$numberOfFiles;
        my $postcount=$numberOfFiles;
        unless ( $timeHash{$timestampArray[$location]} eq "TARGET" ) {
                push(@TARGET_PCAPS,$timeHash{$timestampArray[$location]});
        } else {
                wlog("DEBUG Skipping got target\n") if ($debug);
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
		$config{'MERGECAP'}
		$debug
=cut

sub doExtract{
    my $bpf=shift;
	my $filelistref=shift;
	my $mergefile=shift;
	my @filelist=@{$filelistref};
	my $tempdir=tempdir(CLEANUP => 1);
	
    my @outputpcaps=();
    wlog("DEBUG: Doing Extraction with BPF $bpf into tempdir $tempdir\n") if ($debug);

	# Test if tcpdump can read files, it's a common problem with apparmor - here we can catch it with a nice error
	my $tdrc=system("$config{'TCPDUMP'} -r $filelist[0] -c 1 -w /dev/null 2>/dev/null");
	if ($tdrc) {
	    wlog("ERROR: Problem with tcpdump reading $filelist[0]. Got tcpdump error code $tdrc.");
	    wlog("ERROR: Hint: This must work $config{'TCPDUMP'} -r $filelist[0] -c 1 -w /dev/null") if $debug;
	    return(0,0,0);
	}
	
        foreach (@filelist){
		my $splitstring="$config{'NODENAME'}\.pcap\.";
                (my $pcappath, my $pcapid)=split(/$splitstring/, $_);
                chomp $_;
                my $filename="$tempdir/$mergefile-$pcapid.pcap";
                push(@outputpcaps,$filename);
		
		my $exec="$config{'TCPDUMP'} -r $_ -w $filename $bpf > /dev/null 2>&1";
                $exec="$config{'TCPDUMP'} -r $_ -w $filename $bpf" if ($vdebug) ; # Show tcpdump o/p if debug is on
                
		wlog("DEBUG: Exec was: $exec\n") if ($vdebug);
                `$exec`;
        }

        # Now that we have some pcaps, lets concatinate them into a single file
        unless ( -d "$tempdir" ) {
                die("Tempdir $tempdir not found!")
	}

        wlog("EXTR : Merge command is \"$config{'MERGECAP'} -w $config{'SAVEDIR'}/$mergefile  @outputpcaps\"") if $debug;

        if (system("$config{'MERGECAP'} -w $config{'SAVEDIR'}/$mergefile @outputpcaps")) {
            wlog("ERROR: Unable to merge pcap files.  Verify that merge command exists at $config{'MERGECAP'}");
            return(0,0,0);
        }

	# Calculate a filesize (in human readable format), and a MD5
        my $filesize=`ls -lh $config{'SAVEDIR'}/$mergefile |awk '{print \$5}'`; 
        chomp $filesize;
	open(PCAPMD5, '<', "$config{'SAVEDIR'}/$mergefile") or die("cant open pcap file $config{'SAVEDIR'}/$mergefile to create MD5");
	my $md5=Digest::MD5->new->addfile(*PCAPMD5)->hexdigest;
	close(PCAPMD5);


        # Clean up temp files that have been merged...
	File::Temp::cleanup() unless ($vdebug);

	return($mergefile,$filesize,$md5);
}

=head2 mkreport
	Create a text report about the extraction.
=cut

sub mkreport{
	my $filename=shift;	# Filename to create
	my $request=shift;	# HashRef to request data.	
	my $extract=shift;	# Details about the extract process
	my $bpf=0;

	unless ($request->{'bpf'}) {
		$bpf=OFPC::Common::mkBPF($request);
	} else {

		$bpf=$request->{'bpf'};
	}

	$filename="$config{'SAVEDIR'}/$request->{'tempfile'}.txt" unless ($filename);

	if (open REPORT , '>', $filename)  { 
	
       		print REPORT "###################################\nOFPC Extract report\n" .
			"User: $request->{'user'}\n" .
      		       	"User comment: $request->{'comment'}\n"  .
			"-----------------------------------\n" .
			"Event Type    : $request->{'logtype'}\n" .
			"Event Log     : $request->{'logline'}\n" .
			"Request time  : $request->{'rtime'}\n" .
			"Comment       : $request->{'comment'}\n" .
			"---------------------------\n" ;
		print REPORT "Timestamp     : $request->{'timestamp'} (" . localtime($request->{'timestamp'}) . ")\n" if $request->{'timestamp'};  
		print REPORT "Start Time    : $request->{'stime'} (" . localtime($request->{'stime'}) . ")\n" if $request->{'stime'};  
		print REPORT "End Time      : $request->{'etime'} (" . localtime($request->{'etime'}) . ")\n" if $request->{'etime'};  
		print REPORT "BPF Used      : $bpf\n";
	
		print REPORT "Filename:     : $extract->{'filename'} \n" .
			"Size          : $extract->{'size'} \n" .
			"MD5           : $extract->{'md5'} \n" .
			"Feedback      : $extract->{'message'}\n" .
			"---------------------------\n";
		close(REPORT);
		return($filename);
	} else {
		wlog("PREP: ERROR: Unable to open MetaFile $config{'SAVEDIR'}/$request->{'tempfile'}.txt for writing");
		return(0);
	}
}

=head2 doproxy
	The OFPC "Proxy" action.
	An OpenFPC Proxy device proxies the request from the client to a node, and sends the data back to the client.
	The Proxy action allows ofpc to scale out rather than up, and hopefully be pretty scalable (to be confirmed!)

	Proxy mode is OUT OF SCOPE for the initial release, but I wanted to make sure that it could function sooner rather than later.
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

sub doproxy{
    my $request=shift;
    my %result=(
		message => "None",
		success => 0,
		filename => 0,
		size => 0,
		md5 => 0,
    );
    my $r2=OFPC::Request::mkreqv2();
    my $nodesock = IO::Socket::INET->new(
                                PeerAddr => $request->{'nodehost'},
                                PeerPort => $request->{'nodeport'},
                                Proto => 'tcp',
                                );

    unless ($nodesock) { 
		wlog("PROXY: Unable to open socket to node $request->{'nodehost'}:$request->{'nodeport'}");
		$result{'message'} = "Node: $config{'NODENAME'} unable to connect to node $request->{'nodehost'}:$request->{'nodeport'}";
		$result{'success'} = 0;	
		return(\%result);
    }
    # This is an openfpc-proxy request, we don't want the user to control what file we will
    # write on the proxy. Create our own tempfile.
    $r2->{'filename'}{'val'}="M-$request->{'nodehost'}-$request->{'nodeport'}-" . time() . "-" . $request->{'rid'};
    $r2->{'user'}{'val'} = $request->{'nodeuser'};
    $r2->{'password'}{'val'} = OFPC::Request::mkhash($request->{'nodeuser'},$request->{'nodepass'});
    $r2->{'savedir'}{'val'} = $config{'SAVEDIR'};
    $r2->{'action'}{'val'} = "fetch";
    $r2->{'bpf'}{'val'} = $request->{'bpf'};

    %result=OFPC::Request::request($nodesock,$r2);
	
    # Return the name of the file that we have been passed by the node
    if ($result{'success'} == 1) {
		wlog("PROXY: Success: Received file $result{'filename'} MD5: $result{'md5'} Size $result{'size'} from $request->{'device'} ($request->{'nodehost'})\n");
		# XXX
		wlog("Removing the pathname from the file returned in the proxy request $result{'filename'}") if $debug;
		$result{'filename'} = basename($result{'filename'});
		wlog("Filename is now $result{'filename'}") if $debug;
		return(\%result);
	} else {
		wlog("Proxy: Problem: Issue reported back from node: Result: $result{'success'} Message: $result{'message'}");
		return(\%result);
    }
}

=head2 comms
    Communicate with the client, and if a valid request is made add it on to the processqueue.
        Takes: Nothing,
        Returns: Nothing.
    Leon Ward - 2010
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

    # Print banner to client
    print $client "OFPC READY\n";
    while (my $buf=<$client>) {
    	chomp $buf;
    	$buf =~ s/\r//;
    	# Display everything received in the socket for debug
		#print "$client_ip -> Got data $buf :\n" if ($debug);
        
		switch($buf) {
	            
		    case /USER/ {	# Start authentication process
	                
	                if ($buf =~ /USER:\s+([a-zA-Z1-9]+)/) {
	                    $state{'user'}=$1;	
	                    wlog("COMMS: $client_ip: GOT USER $state{'user'}") if ($debug);
	                        
	                    if ($userlist{$state{'user'}}) {	# If we have a user account for this user
	                            
	        	        my $clen=20; #Length of challenge to send
	                        my $challenge="";
	                        for (1..$clen) {
	                            $challenge="$challenge" . int(rand(99));
	                        }
	                     
	                        wlog("DEBUG: $client_ip: Sending challenge: $challenge\n") if $debug;
	                        print $client "CHALLENGE: $challenge\n";
	                        
	                        wlog("DEBUG: $client_ip: Waiting for response to challenge\n") if $debug;
	                        #my $expResp="$challenge$userlist{$reqh->{'user'}}";
	                            
	                        $state{'response'}=md5_hex("$challenge$userlist{$state{'user'}}");
	                    } else {
	                        wlog("AUTH : $client_ip: AUTH FAIL: Bad user: $state{'user'}");
	                        print $client "AUTH FAIL: Bad user $state{'user'}\n";
	                    }
	                } else {
	               	    wlog("AUTH : $client_ip: Bad USER: request $buf. Sending ERROR");
	                    print $client "AUTH FAIL: Bad user $state{'user'}\n";
	                }
	            }
	            
	        case /RESPONSE/ {
				wlog("DEBUG: $client_ip: Got RESPONSE\n") if ($debug);
	                
				if ($buf =~ /RESPONSE:*\s*(.*)/) {
	                    
	                    my $response=$1;
	                    if ($debug) {
	                        wlog("DEBUG: $client_ip: Expected resp: \'$state{'response'}\'\n");
	                        wlog("DEBUG: $client_ip: Actual resp  : \'$response\'\n");
	                    }
	                    
	                    # Check response hash
	                    if ( $response eq $state{'response'} ) {	
							wlog("AUTH : $client_ip: Pass Okay") if ($debug);
							$state{'response'}=0;		# Reset the response hash. Don't know why I need to, but it sounds like a good idea. 
							$state{'auth'}=1;		# Mark as authed
							print $client "AUTH OK\n";
	                    } else {
							wlog("AUTH : $client_ip: Password Bad");
							print $client "AUTH FAIL\n";
	                    }
				} else {
	                wlog("DEBUG $client_ip: Bad USER: request $buf\n") if ($debug);
	                print $client "ERROR: Bad password request\n";
				}
	        }
	            
	        case /ERROR/ {
	            wlog("DEBUG $client_ip: Got error. Closing connection\n");
	            shutdown($client,2);
	        }
	            
	        case /^REQ/ {	
				my $reqcmd;

				if ($state{'auth'}) {
					# OFPC request. Made up of ACTION||...stuff
					if ($buf =~ /REQ:\s*(.*)/) {
		                $reqcmd=$1;
		                wlog("DEBUG: $client_ip: REQ -> $reqcmd\n") if $debug;
		                    
		                my $request=OFPC::Common::decoderequest($reqcmd);

		                if ($request->{'valid'} == 1) {	# Valid request then...		
							# Generate a rid (request ID for this.... request!).
							# Unless action is something we need to wait for, lets close connection
		                        
							my $position=$queue->pending();
		                        
							if ("$request->{'action'}" eq "store") {
		                            # Create a tempfilename for this store request
		                            $request->{'tempfile'}=time() . "-" . $request->{'rid'} . ".pcap";
		                            print $client "FILENAME: $request->{'tempfile'}\n";
		                            
		                            $queue->enqueue($request);
		                            
		                            #Say thanks and disconnect
		                            wlog("DEBUG: $client_ip: RID: $request->{'rid'}: Queue action requested. Position $position. Disconnecting\n");
		                            print $client "QUEUED: $position\n";
		                            shutdown($client,2);
		                            
							} elsif ($request->{'action'} eq "fetch") {
		                            # Create a tempfilename for this store request
		                            $request->{'tempfile'}=time() . "-" . $request->{'rid'} . ".pcap";
					    			wlog("COMMS: $client_ip: RID: $request->{'rid'} Fetch Request OK -> WAIT!\n");
		                            
					    			# Prep result of the request for delivery (route/extract/compress etc etc)
		                            my $prep = OFPC::Common::prepfile($request);
		                            my $xferfile=$prep->{'filename'};
		                            
		                            if ($prep->{'success'}) {
										wlog("COMMS: $request->{'rid'} $client_ip Sending File:$config{'SAVEDIR'}/$xferfile MD5: $prep->{'md5'}");
										# Get client ready to recieve binary PCAP or zip file
		                                
										if ($prep->{'filetype'} eq "ZIP") {
		                                    print $client "ZIP: $prep->{'md5'}\n";
										} elsif ($prep->{'filetype'} eq "PCAP") {
		                                    print $client "PCAP: $prep->{'md5'}\n";
										} else {
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
										
										wlog("COMMS: $client_ip Request: $request->{'rid'} : Transfer complete") if $debug;
		                                
										# unless configured to keep it, delete the pcap file from
										# this queue instance
		                                
										unless ($config{'KEEPFILES'}) {
		                                    wlog("COMMS: $client_ip Request: $request->{'rid'} : Cleaning up.") if $debug;
		                                    unlink("$config{'SAVEDIR'}/$xferfile") or
		                                     wlog("COMMS: ERROR: $client_ip Request: $request->{'rid'} : Unable to unlink $config{'SAVEDIR'}/$xferfile");
										}
		                            } else {
										print $client "ERROR: $prep->{'message'}\n";
			                        	shutdown($client,2);	# CLose client
		                            }
		                            
							} elsif ($request->{'action'} eq "status") {
		                            
		                        wlog ("COMMS: $client_ip Recieved Status Request");
		                        my $s=OFPC::Common::getstatus($request);
		                        my $sj = encode_json($s);
		                        # print Dumper $s;
		                        wlog("DEBUG: Status msg sent to client \n") if $debug;	
		                        print $client "STATUS: $sj";
			                    shutdown($client,2);
		                           
							} elsif ($request->{'action'} eq "summary") {
		                            
		                        wlog("COMMS: $client_ip: RID: $request->{'rid'} getting summary data\n");
		                        wlog("COMMS: $client_ip: RID: $request->{'rid'} Stime=$request->{'stime'} Etime=$request->{'etime'}");
		                            
		                        #(my $success, my $message, my @table)=OFPC::CXDB::getctxsummary($config{'SESSION_DB_NAME'},  XXX
		                        (my $t)=OFPC::CXDB::getctxsummary($config{'SESSION_DB_NAME'}, 
								$config{'SESSION_DB_USER'}, 
								$config{'SESSION_DB_PASS'},
								$request->{'sumtype'},
								$request->{'stime'},
								$request->{'etime'},
								$request->{'limit'});
		                            
		                        unless ($t->{'error'}) { 
		                        	my $tj=encode_json($t);	
									print $client "TABLE:\n";
									wlog("DEBUG: Sending table JSON....\n") if ($debug);
									print $client $tj . "\n";
		                                    
		                            print $client "\n";
		                        } else {	
									print $client "ERROR: $t->{'error'}\n";
		                        }
		                        wlog("COMMS: $client_ip: RID: $request->{'rid'} Table Sent. Closing connection\n");
			                    shutdown($client,2);
							} elsif ($request->{'action'} eq "search") {
								wlog("COMMS: $client_ip: RID: $request->{'rid'} Search Request\n");
		                        wlog("COMMS: $client_ip: RID: $request->{'rid'} Stime=$request->{'stime'} Etime=$request->{'etime'}");

		                        (my $t)=OFPC::CXDB::cx_search($config{'SESSION_DB_NAME'}, 
												$config{'SESSION_DB_USER'}, 
												$config{'SESSION_DB_PASS'},
												$request);
		                            
		                        unless ($t->{'error'}) { 
		                        	my $tj=encode_json($t);	
									print $client "TABLE:\n";
									wlog("DEBUG: Sending table JSON....\n") if ($debug);
									print $client $tj . "\n";
		                                    
		                            print $client "\n";
		                        } else {	
									print $client "ERROR: $t->{'error'}\n";
		                        }
		                        wlog("COMMS: $client_ip: RID: $request->{'rid'} Table Sent. Closing connection\n");
			                    shutdown($client,2);
							}
		                } else {
							wlog("COMMS: $client_ip: BAD request $request->{'msg'}");
							print $client "ERROR: $request->{'msg'}\n";
			                shutdown($client,2);
		                }
					} else {
		                wlog("DEBUG: $client_ip: BAD REQ -> $reqcmd") if $debug;
		                print $client "ERROR: bad request\n";
		                shutdown($client,2);
					}
				} else {
					wlog("Request from a non authenticated session. Closing");
					print $client "ERROR: Authentication required\n";
					shutdown($client,2);
				}
	                
	        }
	            
	        case /OFPC-v1/ {
				wlog("DEBUG $client_ip: GOT version, sending OFPC-v1 OK\n") if $debug;
	     	    print $client "ERROR: Request format OFPC-v1 is depricated and no longer compatable with OFPC. Please update your OpenFPC Client\n" ;
	        } 
	        case /OFPC-v2/ {
				wlog("DEBUG $client_ip: GOT version, sending OFPC-v2 OK\n") if $debug;
	     	    print $client "OFPC-v2 OK\n" ;
	        } 
	        else {
	        	wlog("COMMS: $client_ip : Bad Request");
				wlog("DEBUG: $client_ip : Bad request was: \"$buf\"\n") if $debug;
				shutdown($client,$2);
		    }
		}
    }
}

=head2 runq
	The runq function operates as a thread waiting for an entry to appear in
	the extraction queue. When found, it then takes action on it.
	
	Takes: Nothing
	Returns: Nothing
	Expects: A shared global var across multiple threads called "queue"
=cut

sub runq {
    
    while (1) {
        sleep(1);                               # Pause between polls of queue
       	my $qlen=$queue->pending();             # Length of extract queue
        
       	if ($qlen >= 1) {                       # If we have something waiting in the queue for processing...
            my $request=$queue->dequeue();      # Pop the request out of the queue, and do something with it.
            
            wlog("RUNQ : Found request: $request->{'rid'} Queue length: $qlen");
            wlog("RUNQ : Request: $request->{'rid'} User: $request->{'user'} Found in queue:");
            
            if ($config{'PROXY'}) {
                # The proxy mode routes the request to a Node,
                # routereq takes a device name, and provides all data required to
                # route the request to said device.
               
				(my $nodehost,my $nodeport,my $nodeuser,my $nodepass)=routereq($request->{'device'});
				if ($nodehost) { 		# If this request is routable....
                    $request->{'nodehost'} = $nodehost;
                    $request->{'nodeuser'} = $nodeuser;
                    $request->{'nodeport'} = $nodeport;
                    $request->{'nodepass'} = $nodepass;
                    
                    wlog("RUNQ : PROXY: Request: $request->{'rid'} Routable (to $nodehost)");    
                    my $result=doproxy($request);
                    wlog("RUNQ : PROXY: Request: $request->{'rid'} Result: $result->{'success'} Message: $result->{'message'}");
                    
                    if ($result->{'success'} ) {
						$pcaps{$request->{'rid'}}=$request->{'filename'} ; # Report done
                    } else {
						$pcaps{$request->{'rid'}}="ERROR" ; # Report FAIL 
                    }
				} else {
                    wlog("RUNQ : No openfpc-route to $request->{'device'}. Cant extract.");
                    $pcaps{$request->{'rid'}}="NOROUTE"; # Report FAIL 
				}
            } else {    # If this device is not a proxy, it must be a NODE.
                
				my $result = donode($request,$request->{'rid'});
				if ($result->{'success'}) {
                    wlog("RUNQ : NODE: Request: $request->{'rid'} Success. File: $result->{'filename'} $result->{'size'} now cached on NODE in $config{'SAVEDIR'}"); 
                    $pcaps{$request->{'rid'}}=$result->{'filename'};
                } else {
                    wlog("RUNQ: NODE: Request: $request->{'rid'} Result: Failed, $result->{'message'}.");    
                }
            }
      	}
    }
}

=head2 readroutes
    Open up an OpenFPC route file, and read in the values to a hash called %route.
    Takes: Nothing,
    Returns: 1 for success, 0 for fail
    Expects: A global called %route;
	     $config{'NODEROUTE'}
=cut

sub readroutes{
    wlog("ROUTE: Reading route data from file: $config{'NODEROUTE'}");
    if ($config{'NODEROUTE'}) {
	
	open NODEROUTE, '<', $config{'NODEROUTE'} or die "Unable to open node route file $config{'NODEROUTE'} \n";
	wlog("ROUTE: Reading route file $config{'NODEROUTE'}");
	
	while(<NODEROUTE>) {
	    chomp $_;
	    unless ($_ =~ /^[# \$\n]/) {
	    	if ( (my $key, my $value) = split /=/, $_ ) {
	    		$route{$key} = $value;	
			wlog("ROUTE: Adding route for $key as $value") if $debug;
	    	}
	    }
	}
	
    	close NODEROUTE;
	
    } else {
	die("No route file defined\n");
    }
}

=head readpasswd
    Read in the config file, store it in the %config global variable.
    - Leon Ward 2011
    
    Expects: $configfile
    Returns: 1 for success, 0 for fail.
    Depends on: A global %userlist
=cut

sub readpasswd{

    my $configfile=shift;
    
    open my $config, '<', $configfile or die "ERROR: Unable to open passwd file $configfile $!\n";
    while(<$config>) {
        chomp;
        if ( $_ =~ m/^[a-zA-Z]/) {
            (my $key, my @value) = split /=/, $_;
            if ($key eq "SHA1") {
                wlog("DEBUG: Adding user \"$value[0]\" PassHash \"$value[1]\"\n") if ($debug);
                $userlist{$value[0]} = $value[1] ;
            }
        }
    }
    close $config;
    
    return(%config);    
}

=head readconfig
    Read in the config file, store it in the %config global variable.
    - Leon Ward 2011
    
    Expects: $configfile
    Returns: 1 for success, 0 for fail.
    Depends on: A global %config
=cut

sub readconfig{

    my $configfile=shift;
    
    unless ($configfile) {
        die "Please specify a config file. See help (--help)\n";
    }
    
    open my $config, '<', $configfile or die "Unable to open config file $configfile $!";
    while(<$config>) {
        chomp;
        if ( $_ =~ m/^[a-zA-Z]/) {
            (my $key, my @value) = split /=/, $_;
            unless ($key eq "USER") {
		if ($value[0]){
		    $config{$key} = join '=', @value;
		}
            } else {
                wlog("DEBUG: Adding user \"$value[0]\" Pass \"$value[1]\"\n") if ($debug);
                $userlist{$value[0]} = $value[1] ;
            }
        }
    }
    close $config;
    return(%config);    
}

1;
