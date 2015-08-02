package OFPC::Common;

#########################################################################################
# Copyright (C) 2011 - 2014 Leon Ward
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
use Data::UUID;
our @ISA = qw(Exporter);
@EXPORT = qw(wlog);
@EXPORT_OK = qw(ALL);
$VERSION = '0.5';

=head2 wantdebug
	Check if debug is enabled via a shell variable OFPCDEBUG=1
	If so, return a value that enables debug in this function.
=cut

sub wantdebug{
	my $var="OFPCDEBUG";

	my $debug=$ENV{$var};
	return($debug);
}

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
	Generate a "unique" request ID for the extraction request.
	Using a GUID for each extraction
=cut

sub getrequestid{
	$mrid++;
	my $ug = new Data::UUID;
	my $rguid=$ug->create_str();

	wlog("COMMS: Request GUID is $rguid\n") if $debug;
	return($rguid);
}


sub validatepcaplist{
	# Take a list of pcap file, check none are 0 bytes long and they can all be read
	# returns a list of the valid files only
	my @inlist = @_;
	my @filelist=(); 	# Chomped version of inlist;
	my $debug=1;
	my @goodfiles=();

	foreach (@inlist){
		chomp $_;
		push(@filelist, $_);
	}

	wlog("DEBUG: Validating list of pcap files @filelist") if $debug;

	foreach (@filelist) {
		if ( -s $_ ) {
			my $tdrc=system("$config{'TCPDUMP'} -r $_ -c 1 -w /dev/null 2>/dev/null");
			if ($tdrc) {
	    		wlog("ERROR: Problem with tcpdump reading $_. Got tcpdump error code $tdrc.");
	    		wlog("ERROR: Hint: This must work $config{'TCPDUMP'} -r $_ -c 1 -w /dev/null") if $debug;
			} else {
				wlog("DEBUG: Looks like $_ reads fine, keeping file on list") if $vdebug;
				push(@goodfiles, $_);
			}
		} else {
			wlog("DEBUG: PCAP validation: $_ is 0 bytes long, removing it from the list") if $debug;
		}
	}
	wlog("DEBUG: PCAP validation: Clean file list provided back is @goodfiles") if $vdebug;
	return(@goodfiles);
}

sub checkbpf{
        my $bpf=shift;
        my $debug=wantdebug();
        # Check BPF to ensure it's valid before doing anything with it.
        unless ($bpf =~/^[A-Za-z0-9 \.\[\]\(\)&=\/]+$/) {
                wlog("DEBUG: BPF Failed input validation, bad chars in $bpf");
                return(0);
        }
        # To check BPF is valid, open a pcap for reading. This only works on a Node where there is a pcap file
        # Just return succes if we are a proxy
        if ($config{'PROXY'}) {
        	wlog("Not validating BPF on a proxy node") if $debug;
        	return(1);
        }
        my @pcaptemp = `ls -rt $config{'BUFFER_PATH'}/openfpc-$config{'NODENAME'}.pcap.*`;
        @pcaptemp = validatepcaplist(@pcaptemp);  # check for any bad files and remove them form the list

        if (@pcaptemp) {
                my $p=shift(@pcaptemp);
                chomp $p;
                my $bc="$config{'TCPDUMP'} -nnr $p -c 1 \"$bpf or not($bpf)\" > /dev/null 2>&1";
                wlog("DEBUG: Now extracting from $p");
                my $i=system($bc);
                if ($i) {
                        wlog("WARN : BPF failed to validate - $bpf");
						wlog("Command used to validate BPF was: $bc") if $debug;
						wlog("Retrun was $i") if $debug;
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
	my $r=shift;
        my @eventbpf=();
        my $bpfstring;
        my $debug=wantdebug();
        if ($debug) {
	        wlog("MKBPF: Building bpf from:");
    	    wlog("MKBPF: SIP: $r->{'sip'}{'val'}, DIP: $r->{'dip'}{'val'}");
        	wlog("MKBPF: SPT: $r->{'spt'}{'val'}, DPT: $r->{'dpt'}{'val'}");
        	wlog("MKBPF: Proto $r->{proto}{'val'}");
        };

        if ($r->{'proto'}{'val'}) {
                $r->{'proto'}{'val'} = lc $r->{'proto'}{'val'}; 				# In case the tool provides a protocol in upper case
        }

        if ( $r->{'sip'}{'val'} xor $r->{'dip'}{'val'} ) { # One sided bpf
                if ($r->{'sip'}{'val'} ) { push(@eventbpf, "host $r->{'sip'}{'val'}" ) }
                if ($r->{'dip'}{'val'} ) { push(@eventbpf, "host $r->{'dip'}{'val'}" ) }
        }

        if ( $r->{'sip'}{'val'} and $r->{'dip'}{'val'} ) {
                 push(@eventbpf, "host $r->{'sip'}{'val'}" );
                 push(@eventbpf, "host $r->{'dip'}{'val'}" );
        }

        if ( $r->{'proto'}{'val'} ) {
                 push(@eventbpf, "$r->{'proto'}{'val'}" );
		}

        if ( $r->{'spt'}{'val'} xor $r->{'dpt'}{'val'} ) {
                if ($r->{'spt'}{'val'} ) { push(@eventbpf, "port $r->{'spt'}{'val'}" ) }
                if ($r->{'dpt'}{'val'} ) { push(@eventbpf, "port $r->{'dpt'}{'val'}" ) }
        }

        if ( $r->{'spt'}{'val'} and $r->{'dpt'}{'val'} ) {
                 push(@eventbpf, "port $r->{'spt'}{'val'}" );
                 push(@eventbpf, "port $r->{'dpt'}{'val'}" );
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

        wlog("MKBPF: Built bpf \"$bpfstring\"") if $debug;;
        my $valid=checkbpf($bpfstring);
        if ($valid) {
        	wlog("DEBUG: MKBPF: BPF looks valid") if $debug;
	        return($bpfstring);
        } else {
        	wlog("DEBUG: MKBPF: Bad BPF") if $debug;
        	return(0);
        }
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
		message => "None",
	);
	my $debug=wantdebug();
	wlog("STATU: Getting node status data") if $debug;
	# Supported types for text format conversion are
		# e = time epoch
		# t = text
		# b = binary
		# s = space (bytes)
		# p = %a

	my $ltz=DateTime::TimeZone->new( name => 'local' )->name();
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
		description => {
			val => $config{'DESCRIPTION'},
			text => "Description                    ",
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
		sessiontime => {
			val => 0,
			text => "Storage Window                 ",
			type => "t",
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
		lastctx => {
			val => 0,
			text => "Newest session in storage      ",
			type => "e",
		},
		nodetz => {
			val => 0,
			text => "Node Timezone                  ",
			type => "t",
		},
		localtime => {
			val => 0,
			text => "Local time on node             ",
			type => "e",
		},
		ltz => {
			val => 0,
			text => "Local time on node             ",
			type => "e",
		},
	);

	unless ($config{'PROXY'}) { 	# Process as a node. Don't check proxy specific stuff like comms
		$s{'ofpctype'}{'val'} = "NODE";
		$s{'nodename'}{'val'} = $config{'NODENAME'};
		# Get timestamp of oldest pcap buffer
		unless (opendir(DIR,$config{'BUFFER_PATH'}) ) {
			$s{'message'}{'val'} = "Unable to open buffer path $config{'BUFFER_PATH'}";
			wlog("STATU: Error, unable to open buffer path $config{'BUFFER_PATH'}");
			return \%s;
		}
		my @files=readdir(DIR);
		unless (@files) {
			$s{'message'}{'val'}= "Unable to open buffer path $config{'BUFFER_PATH'}";
			wlog("STATU: Error, unable to open buffer path $config{'BUFFER_PATH'}");
			return \%s;
		}
		@files=sort(@files);

		# A sorted dir could also include other files. We can apply a check for the daemonlogger prfix
		# to make sure we don't end up with some other crap, or ".",".." etc

		my $oldestfile=0;
		foreach (@files) {
			if ($_  =~ /$config{'NODENAME'}\.pcap/) {
				$oldestfile=$_;
				wlog("STATU: DEBUG: Oldest PCAP file is $oldestfile") if $debug;
				last;
			}
		}

		if ( $oldestfile =~ /$config{'NODENAME'}\.pcap\.([0-9]+)/ ) {
			$s{'firstpacket'}{'val'} = $1;
			wlog("STATU: DEBUG: First packet is $oldestfile") if $debug;
		}

		# Get disk space info
		##############################
		my $packetref=df("$config{'BUFFER_PATH'}");
		$s{'packetspace'}{'val'} = $packetref->{'per'};
		$s{'packetused'}{'val'} = $packetref->{'used'};
		wlog("STATU: DEBUG: Packet used is $packetref->{'used'} \n") if $debug;

		if ($config{'ENABLE_SESSION'}) {
			my $sessionref=df("$config{'SESSION_DIR'}");
			wlog("SATUS: DEBUG: Session dir is $config{'SESSION_DIR'}") if $debug;
			if (defined $sessionref) {
				$s{'sessionspace'}{'val'} = $sessionref->{'per'};
				$s{'sessionused'}{'val'} = $sessionref->{'used'};
				wlog("STATU: DEBUG: Session storage space used is $sessionref->{'used'}") if $debug;
				wlog("STATU: DEBUG: Session storage space pct is $sessionref->{'per'}") if $debug;
			} else {
				wlog("STATU: ERROR: Unable to access session storage dir to gather stats $config{'SESSION_DIR'}");
				$s{'sessionspace'}{'val'} = "Error: Unable to access session dir $config{'SESSION_DIR'}";
				$s{'sessionused'}{'val'} = "Error: Unable to access session dir $config{'SESSION_DIR'}";
				$s{'sessionspace'}{'type'} = "t";
				$s{'sessionused'}{'type'} = "t";
			}
		} else {
			$s{'sessionspace'}{'type'} = "t";
			$s{'sessionused'}{'type'} = "t";
			$s{'sessionspace'}{'val'} = "Disabled";
			$s{'sessionused'}{'val'} = "Disabled";
		}

		# Get summary of pcap file total space in this buffer
		################################
		my $ps=`du -hsc $config{'BUFFER_PATH'}/openfpc-$config{'NODENAME'}\.pcap* |grep total`;
		(my $pso)=split(/\s/,$ps);
		wlog ("STATU: DEBUG: Packet Space Overall (pso) is '$pso'") if $debug;
		$s{'packetpacptotal'}{'val'} = $pso;

		my $saveref=df("$config{'SAVEDIR'}");
		$s{'savespace'}{'val'} = $saveref->{'per'};
		$s{'saveused'}{'val'} = $saveref->{'used'};
		wlog("STATU: DEBUG: Savespace in $config{'SAVEDIR'} is $s{'savespace'}{'val'} \n") if $debug;

		# Grab uptime and load average data
		####################################
		my $uptime=`uptime`;
		chomp $uptime;
		if ($uptime =~ /load average.*:\s*([0-9]\.[0-9]+),*\s*([0-9]\.[0-9]+),*\s*([0-9]\.[0-9]+)/){
			$s{'ld1'}{'val'} = $1;
			$s{'ld5'}{'val'} = $2;
			$s{'ld15'}{'val'} = $3;
		}
		$s{'localtime'}{'val'} = time();

		# Get session DB data
		#################################
		if ($config{'ENABLE_SESSION'}) {
			wlog("STATU: DEBUG: Session data enabled on this node. Checking DB status") if $debug;
			if ( my $dbh= DBI->connect("dbi:mysql:database=$config{'SESSION_DB_NAME'};host=localhost",$config{'SESSION_DB_USER'},$config{'SESSION_DB_PASS'}) ) {

			    # Get count of sessions in DB
			    my $sth= $dbh->prepare("SELECT COUNT(*) FROM session") or wlog("STATUS: ERROR: Unable to get session table size $DBI::errstr");
			    if ( $sth->execute() ) {
			        while ( my @row = $sth->fetchrow_array ) {
			        	$s{'sessioncount'}{'val'} = $row[0];
					}
			    } else {
				    wlog("STATU: ERROR: Unable to exec SQL command");
			    }
			    wlog("STATU: DEBUG: Session DB size is $s{'sessioncount'}{'val'} sessions\n") if $debug;

			    # Get Oldest session time
			    $sth= $dbh->prepare("SELECT unix_timestamp(start_time) FROM session ORDER BY start_time LIMIT 1") or wlog("STATUS: ERROR: Unable to get oldest conenction $DBI::errstr");
			    $sth->execute() or wlog("STATUS: ERROR: Unable to exec SQL command");
			    while ( my @row = $sth->fetchrow_array ) {
  					$s{'firstctx'}{'val'} = $row[0];
			    }
			    $s{'firstctx'}{'val'} = OFPC::Parse::norm_time($s{'firstctx'}{'val'},"UTC");
			    wlog("STATU: DEBUG: Oldest connection in session DB is $s{'firstctx'}{'val'}\n") if $debug;

			    # Get Newest session time
			    $sth= $dbh->prepare("SELECT unix_timestamp(start_time) FROM session ORDER BY start_time desc LIMIT 1") or wlog("STATUS: ERROR: Unable to get newest conenction $DBI::errstr");
			    $sth->execute() or wlog("STATUS: ERROR: Unable to exec SQL command");
			    	while ( my @row = $sth->fetchrow_array ) {
  						$s{'lastctx'}{'val'} = $row[0];
			    	}
			    $s{'lastctx'}{'val'} = OFPC::Parse::norm_time($s{'lastctx'}{'val'},"UTC");
			    wlog("STATU: DEBUG: Newest connection in session DB is $s{'lastctx'}{'val'}\n") if $debug;

			    $dbh->disconnect or wlog("Unable to disconnect from DB $DBI::errstr");
			    if (opendir(SESSION_DIR,$config{'SESSION_DIR'}) ) {
					while (my $filename=readdir(SESSION_DIR)) {
				      	$s{'sessionlag'}{'val'}++ unless $filename =~ /^(\.|failed)/;
			    	}
			    }
			    my $sw = $s{'lastctx'}{'val'} - $s{'firstctx'}{'val'};


			    my $sd = int($sw/(24*60*60));
				my $sh = ($sw/(60*60))%24;
				my $sm = ($sw/60)%60;
				my $ss = $sw%60;

				$s{'sessiontime'}{'val'} = "$sd Days, $sh Hours, $sm Minutes, $ss Seconds";

			} else {
				wlog("DEBUG: Unable to connect to DB for stats info");
				$s{'sessioncount'}{'val'} = "Unable to connect to session DB";
				$s{'firstctx'}{'val'} = "Unable to connect to session DB";
				$s{'lastctx'}{'val'} = "Unable to connect to session DB";
				$s{'sessiontime'}{'val'} = "Unable to connection to session DB";
				$s{'sessioncount'}{'type'} = "t";
				$s{'firstctx'}{'type'} = "t";
				$s{'lastctx'}{'type'} = "t";
			}
		} else {
			wlog("DEBUG: Session data disabled on this node");
		}
		# Node TZ
		$s{'nodetz'}{'val'}=$ltz;

		# Check we are providing back some valid data
		if ( $s{'ld1'}{'val'} and $s{'nodename'}{'val'} ) {
			$s{'success'}{'val'} = 1;
		}

		# Put the node status hash into a container that can scale for multiple nodes
		$sc{'nodename'} = $config{'NODENAME'};
		push (@{$sc{'nodelist'}},$config{'NODENAME'});
		$sc{'success'} = $s{'success'};
		$sc{$config{'NODENAME'}} = \%s;

	} else {

		# This node is a proxy...
		# Hash of status data we want the proxy to tell us about
		# State of connections,
		# DB size
		# etc etc

		my %ps = (
			success => {
				val => 1,
				text => "Request Status                 ",
				type => "t",
			},
			nodename => {
				val => $config{'NODENAME'},
				text => "Node Name                      ",
				type => "t",
			},
			description => {
				text => "Description                    ",
				val => $config{'DESCRIPTION'},
				type => "t",
			},
			ofpctype => {
				val => "PROXY",
				text => "Node Type                      ",
				type => "t",
			},
			upnodes => {
				val => "",
				text => "Nodes Up                       ",
				type => "t",
			},
			downnodes => {
				val => "",
				text => "Nodes Down                     ",
				type => "t",
			},
		);

		$sc{'message'} = "None";
		#$sc{'ofpctype'} = "Proxy";
		$sc{'nodename'} = $config{'NODENAME'};
		$sc{'ofpctype'} = "PROXY";
		$sc{'proxy'} = 1;
		$sc{'success'} = 1;
		my $rt=readroutes();
		my $b;
		my $scr=\%sc;		# Convert sc (status containter) into a ref
		# Add the proxy node to the node list
		push (@{$sc{'nodelist'}},$config{'NODENAME'});

		#print Dumper $request;
		
		foreach (keys %$rt) {
			wlog("Proxy making status request to node $rt->{$_}{'name'}");
			my $rn=$rt->{$_}{'name'};
			push (@{$sc{'nodelist'}},$rt->{$_}{'name'});
 			my $r2=OFPC::Request::mkreqv2();
    		my $nodesock = IO::Socket::INET->new(
                                PeerAddr => $rt->{$_}{'ip'},
                                PeerPort => $rt->{$_}{'port'},
                                Proto => 'tcp',
                                );
	    	if ($nodesock) {
				wlog("Connected to node $rt->{$_}{'name'}");
	    		$r2->{'user'}{'val'} =  $request->{'user'}{'val'};
    			$r2->{'password'}{'val'} = $request->{'password'}{'val'};
    			$r2->{'action'}{'val'} = "status";
    			my %s=OFPC::Request::request($nodesock,$r2);

    			unless ($s{'success'}) {
    				wlog("ERROR: issue found with making status request to node");
    				wlog($s{'message'});
    			}
    			print Dumper \%s;
    			# Add node to Live list
    			$ps{'upnodes'}{'val'} = $ps{'upnodes'}{'val'} . $rt->{$_}{'name'} . " ";
    			my $sr = \%s;
    			# Add the data from the status data back from the node to the container hash
    			$scr->{$rt->{$_}{'name'}} = $sr->{$rt->{$_}{'name'}};
    		} else {
    			wlog("STATU: Unable to Connect to node $rt->{$_}{'name'}");
    			wlog("STATU: DEBUG: Adding $rt->{$_}{'name'} to down nodes list") if $debug;

    			$ps{'downnodes'}{'val'} = $ps{'downnodes'}{'val'} . $rt->{$_}{'name'} . " ";
    		}
		}
		# Add the proxy status data to the hash in the same was as we would a node
		my $psr = \%ps;
		$scr->{$config{'NODENAME'}} = $psr;
	}
	return(\%sc);
}

=head2 trimsessiondb
	The Session DB doesn't have a need to be larger than the oldest packet.
=cut

sub trimsessiondb(){

	my $trimtime=0;		# New value of oldest ctx
	wlog("TRIM: Waking up to trim session DB");
	my $status=OFPC::Common::getstatus();
	my $fc=$status->{$config{'NODENAME'}}{'firstctx'}{'val'};
	my $fp=$status->{$config{'NODENAME'}}{'firstpacket'}{'val'};
	my $debug=wantdebug();

	wlog("TRIM: Trimming Session DB from: $fc (" . localtime($fc) . ") to $fp (". localtime($fp) . ")") if $debug;

	if (my $dbh= DBI->connect("dbi:mysql:database=$config{'SESSION_DB_NAME'};host=localhost",$config{'SESSION_DB_USER'},$config{'SESSION_DB_PASS'})) {
		my $sth= $dbh->prepare("DELETE FROM session WHERE unix_timestamp(start_time) < $fp")
			or wlog("STATUS: ERROR: Unable to prep query $DBI::errstr");
		if ($sth->execute()) {
			$trimtime=$fp;
		} else {
		 	wlog("STATUS: ERROR: Unable to trim session DB");
		}
		$dbh->disconnect or wlog("Unable to disconnect from DB $DBI::errstr");
	} else {
		wlog("DEBUG: Unable to connect to Session DB - Won't try to trim sessions");
	}
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
	Although it looks like we're simply duplicating data, bit it enables input validation to ensure we've got the data that is expected from a user.

=cut

sub decoderequest($){
	my $rj=shift;
	my $now=time();
    my $rawrequest=$rj;
    my $gr=OFPC::Request::mkreqv2();		# Good req hash
    my $r;								# Request href, filled from the rj json
    my $debug=wantdebug();
    wlog("DECOD: Decoding request");
    unless ($r=decode_json($rj)) {
    	wlog("DECOD: ERROR: Failed to decode request JSON");
    	$gr->{'msg'}{'val'} = "Bad request. Unable to parse JSON.";
    	$gr->{'fail'}{'val'} = 1;
    	return($gr);
    }

    $gr->{'valid'}{'val'} = 0;				# Set to valid after decoding and checking
	$gr->{'rtime'}{'val'} = gmtime();
	$gr->{'metadata'}{'rid'} = OFPC::Common::getrequestid;
	# Copy values from the client JSON request into the server request hash.
	$gr->{'user'}{'val'}		=	$r->{'user'}{'val'};
	$gr->{'password'}{'val'}	=	$r->{'password'}{'val'};
	$gr->{'action'}{'val'}		=	$r->{'action'}{'val'}; 			# Action (store,status,fetch,etc)
	$gr->{'device'}{'val'} 		=	$r->{'device'}{'val'};			# Device to request from i.e openfpc-node
	$gr->{'filename'}{'val'} 	= 	$r->{'filename'}{'val'};		# Filename to save file as
	$gr->{'filetype'}{'val'} 	= 	$r->{'filetype'}{'val'};		# Filetype zip or pcap?
	$gr->{'logtype'}{'val'} 	= 	$r->{'logtype'}{'val'};			# Type of log being processed
	$gr->{'logline'}{'val'}		= 	$r->{'logline'}{'val'};			# The log-line (including one made from session identifiers # KILL
	$gr->{'comment'}{'val'} 	= 	$r->{'comment'}{'val'};			# User comments
	$gr->{'limit'}{'val'}		= 	$r->{'limit'}{'val'}; 			# Limit number of connections

	$gr->{'action'}{'val'} = lc $r->{'action'}->{'val'};				# Ensure action is lower case
	wlog("DECOD: DEBUG: Received action $gr->{'action'}{'val'}") if ($debug);


	# fetch, store and search all have the same time constraints.
	# normalizing them once and only once.

	if ($gr->{'action'}{'val'} =~/(fetch|store|search)/) {
		wlog("DECOD: DEBUG: Normalizing timestamps") if $debug;
		foreach ('timestamp', 'stime', 'etime') {
			if ($r->{$_}{'val'}) {
				wlog("DECOD: DEBUG: $_ in request was: $r->{$_}{'val'}") if $debug;
				$gr->{$_}{'val'} = OFPC::Parse::norm_time($r->{$_}{'val'});
				wlog("DEBUG: DEBUG: $_ normalized to $gr->{$_}{'val'} (" . localtime($gr->{$_}{'val'}) . ")") if $debug;
			} else {
				wlog("DECOD: DEBUG: $_ not set in request. Nothing to normalize") if $debug;
			}
		}
	}

	if ($gr->{'action'}{'val'} =~/(fetch|store)/) {

		# Data could be requested in multiple forms, need to choose a priority order in case multiple appear in the same request
		# 1 bpf
		# 2 session identifiers
		# 3 logline

		if ($r->{'bpf'}{'val'}) {
			wlog("DECOD: DEBUG: Found BPF set as $r->{'bpf'}{'val'}\n") if $debug;
            # Check BPF to ensure it's valid before doing anything with it.
            my $bpfcheck = checkbpf($r->{'bpf'}{'val'});
            if ($bpfcheck==1) {
            	# Good BPF
                $gr->{'bpf'}{'val'} = $r->{'bpf'}{'val'};
            } elsif ($bpfcheck==2) {
            	# Unable to check BPF because of tcpdump error
                $gr->{'msg'}{'val'} .= "No pcap files found in buffer path";
                $gr->{'fail'}{'val'} = 1;
                return($gr);
                # Return here, or add all of the fails and return at the end?
            } else {
            	# Bad BPF
                $gr->{'msg'}{'val'} .= "BPF Failed input validation";
                $gr->{'fail'}{'val'} = 1;
                return($gr);
            }
		} elsif ($r->{'logline'}{'val'}) {
			wlog("DECOD: DEBUG: Found logline requested as $r->{'logline'}{'val'}\n") if $debug;

			# Check logline is valid
			my ($eventdata)=OFPC::Parse::parselog($r->{'logline'}{'val'}, $r);

			unless ($eventdata->{'parsed'}) {
				wlog("DECOD: ERROR: Cannot parse logline");
				$gr->{'msg'}{'val'} .= "Unable to parse logline \"$r->{'logline'}{'val'}\" ";
				$gr->{'fail'}{'val'} = 1;
				return($gr);
			} else {
				# Event data was decoded from logline
				# Append the session that is being requested to the hash that is the request itself
				$gr->{'sip'}{'val'} = $eventdata->{'sip'};
				$gr->{'dip'}{'val'} = $eventdata->{'dip'};
				$gr->{'spt'}{'val'} = $eventdata->{'spt'};
				$gr->{'dpt'}{'val'} = $eventdata->{'dpt'};
				$gr->{'msg'}{'val'} = $eventdata->{'msg'};
				$gr->{'proto'}{'val'} = $eventdata->{'proto'};
				$gr->{'timestamp'}{'val'} = $eventdata->{'timestamp'};
				wlog("DECOD: DEBUG: logline timestamp has been set to $gr->{'timestamp'}{'val'} (" . localtime($gr->{'timestamp'}{'val'}) . "). Stime is $gr->{'stime'}{'val'}, etime is $gr->{'etime'}{'val'}\n") if $debug;
			}
		} else {
			wlog("DECOD: DEBUG: No BPF or logline detected in request, using session identifiers") if $debug;
			$gr->{'sip'}{'val'} = $r->{'sip'}{'val'};
			$gr->{'dip'}{'val'} = $r->{'dip'}{'val'};
			$gr->{'spt'}{'val'} = $r->{'spt'}{'val'};
			$gr->{'dpt'}{'val'} = $r->{'dpt'}{'val'};
			$gr->{'proto'}{'val'} = $r->{'proto'}{'val'};
			wlog("DECOD: DEBUG: Timestamp is $r->{'timestamp'}{'val'}") if $debug;
			wlog("DECOD: DEBUG: Session IDs sip: \'$r->{'sip'}{'val'}\' dip: \'$r->{'dip'}{'val'}\' spt: \'$r->{'spt'}{'val'}\' dpt: \'$r->{'dpt'}{'val'}\' proto: \'$r->{'proto'}{'val'}\'") if $debug;

		}

		# Default to PCAP file if filetype not specified
		unless ($r->{'filetype'}{'val'}) {
			$gr->{'filetype'}{'val'} = "PCAP";
		}

		wlog("DECOD: User $gr->{'user'}{'val'} assigned RID: $gr->{'metadata'}{'rid'} for action $gr->{'action'}{'val'}. Comment: $gr->{'comment'}{'val'} Filetype : $gr->{'filetype'}{'val'}");
		$gr->{'valid'}{'val'} = 1 unless $gr->{'fail'}{'val'};

	} elsif ($r->{'action'}{'val'} =~/status/) {
		wlog("DECOD: DEBUG: Status request") if ($debug);
		$gr->{'valid'}{'val'} = 1;
	} elsif ($r->{'action'}{'val'} =~/search/) {
		wlog("DECOD: DEBUG: Search request") if ($debug);
		$gr->{'sip'}{'val'} = $r->{'sip'}{'val'};
		$gr->{'dip'}{'val'} = $r->{'dip'}{'val'};
		$gr->{'spt'}{'val'} = $r->{'spt'}{'val'};
		$gr->{'dpt'}{'val'} = $r->{'dpt'}{'val'};
		$gr->{'proto'}{'val'} = $r->{'proto'}{'val'};
		# Search needs to have at least one session identifier to work.
		if ( $gr->{'sip'}{'val'} || $gr->{'dip'}{'val'} || $gr->{'spt'}{'val'} || $gr->{'dpt'}{'val'} || $gr->{'proto'}{'val'}) {
			$gr->{'valid'}{'val'} = 1;
		} else {
			$gr->{'msg'}{'val'} = "Search requires valid session identifiers. Note that flow search by BPF is not supported.";
			wlog("DECOD: ERROR: $gr->{'msg'}{'val'}");
		}

	} elsif ($r->{'action'}{'val'} =~/apikey/) {
		wlog("DECOD: Received action apikey");
		$gr->{'valid'}{'val'} = 1;

	} else {
		# Invalid action
		wlog("DECOD: Received invalid action $gr->{'action'}{'val'}");
		$gr->{'msg'}{'val'} = "received invalid action $gr->{'action'}{'val'}";
	}

	unless ($gr->{'comment'}{'val'}) {
		$gr->{'comment'}{'val'} = "No comment";
	}

	# If no timestamp, stime or etime have been specified, set a default range to search
	unless ($r->{'timestamp'}{'val'}) {
		wlog("DECOD: DEBUG: No value for timestamp has been passed from the user requets");
		if ($r->{'stime'}{'val'} and $r->{'etime'}{'val'}) {
			wlog("DECOD: Final stime and etime are set in request as $r->{'stime'}{'val'} / $r->{'etime'}{'val'}\n") if $debug;
		} else {
			wlog("DECOD: Neither timestamp or stime/etime are set in request, setting timestamp to now ($now)" . localtime($now)) if $debug;
			if ($r->{'last'}{'val'}) {
				wlog("DECOD: DBEUG: Last value set in request. Updating stime and etime to skew now ($now)");
				$gr->{'stime'}{'val'} = $r->{'timestamp'}{'val'} - $r->{'last'}{'val'};
				$gr->{'etime'}{'val'} = $r->{'timestamp'}{'val'};
				wlog("DECOD: DEBUG: stime now " . localtime($gr->{'stime'}{'val'})) if $debug;
				wlog("DECOD: DEBUG: etime now " . localtime($gr->{'etime'}{'val'})) if $debug;
			} else {
				wlog("DECOD: DEBUG: Last not set, defaulting to now") if $debug;
				$gr->{'timestamp'}{'val'} = $now;
			}
		}
	} else {
		wlog("DECOD: DEBUG: Timestamp was passed in initial request from user as $r->{'timestamp'}{'val'}" . localtime($r->{'timestamp'}{'val'})) if $debug;
		if ($r->{'last'}{'val'}) {
			wlog("DECOD: DEBUG: ** Last value set in request as $r->{'last'}{'val'}. Updating stime and etime to skew times from timestamp $r->{'timestamp'}{'val'} " . localtime($r->{'timestamp'}{'val'}));
			$gr->{'stime'}{'val'} = $r->{'timestamp'}{'val'} - $r->{'last'}{'val'};
			$gr->{'etime'}{'val'} = $r->{'timestamp'}{'val'};
			wlog("DECOD: DEBUG: stime now $gr->{'stime'}{'val'} " . localtime($gr->{'stime'}{'val'}));
			wlog("DECOD: DEBUG: etime now $gr->{'etime'}{'val'} " . localtime($gr->{'etime'}{'val'}));
		} else {
			wlog("DECOD: DEBUG: Last not set, defaulting to now") if $debug;
			$gr->{'timestamp'}{'val'} = $now;
		}
	}

    return($gr);
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

		(
		  success => 0,
		  filename => 0,
		  message => 0,
		  filetype => 0,
		  md5 => 0,
		  size => 0,
		  rid => <GUID for request>
		  extract => {
			totalspace => 0,
			searchspace => 0,
			searchtime => 0,
		  },
		)

		success 1 = Okay 0 = Fail
		filename = Name of file (no path!)
		message = Error message
		filetype "PCAP" = pcap file "ZIP" = zip file
=cut

sub prepfile{
    my $r=shift;			# Request hash
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
        rid => $r->{'metadata'}{'rid'},
        buffer => {
        	totalspace => 0,
        	searchspace => 0,
        	searchtime => 0,
        },
    );
	my $debug=wantdebug();

    # If a specific filetype is requested, set prep to gather it
    if ($r->{'filetype'}{'val'} eq "ZIP") {
        $multifile=1;
        $prep{'filetype'} = "ZIP";
    }

    # If we are an openfpc-proxy, check if we need to frag this req into smaller ones, and get the data back from each node
    # If we are node, do the node action now (rather than enqueue if we were in STORE mode)
    # Check if we want to include the meta-text
    # Return the filename of the data that is to be sent back to the client.

    if ( $config{'PROXY'} ) {
			# Check if we can route this request

 			(my $nodehost,my $nodeport,my $nodeuser,my $nodepass)=routereq($r->{'device'}{'val'});
			unless ($nodehost) { 	# If request isn't routeable....
			# Request from all devices
      wlog("PREP : Request is NOT routable. Requesting from all nodes SOUTH from this proxy");
	    $multifile=1;	# Fraged request will be a multi-file return so we use a ZIP to combine
	    foreach (keys %route) {
 				($nodehost,$nodeport)=routereq($_);
				$r->{'metadata'}{'nodehost'}= $nodehost;
				$r->{'metadata'}{'nodeuser'}= $r->{'user'}{'val'};
				$r->{'metadata'}{'nodeport'}= $nodeport;
				$r->{'metadata'}{'nodepass'}= $r->{'password'}{'val'};

				my $result=doproxy($r);
				if ($result->{'success'}) {
      		wlog("DEBUG: Adding $result->{'filename'} to zip list") if ($debug);
      		push (@nodefiles, $result->{'filename'});
				} else {
        	$prep{'message'} = $result->{'message'};
				}
      }
		} else { 					# Route-able, do the proxy action
        	$r->{'metadata'}{'nodehost'} = $nodehost;
        	$r->{'metadata'}{'nodeuser'} = $nodeuser;
        	$r->{'metadata'}{'nodeport'} = $nodeport;
        	$r->{'metadata'}{'nodepass'} = $nodepass;
					wlog("PREP: DEBUG: Taking proxy action on this request\n") if $debug;
        	my $result=doproxy($r);

        	if ($result->{'success'}) {
				$prep{'success'} = 1;
				$prep{'md5'} = $result->{'md5'};
				$prep{'filetype'} = "PCAP";
				$prep{'filename'}="$result->{'filename'}";
				$prep{'rid'}=$r->{'metadata'}{'rid'};
       			push (@nodefiles, $result->{'filename'});
				wlog("PREP : Added $result->{'filename'} to zip list") if ($debug);
        	} else {
				$prep{'message'} = $result->{'message'};
				wlog("Error: $result->{'message'}");
        	}
		}

		# If we are sending back a zip, add the report file
		if ($prep{'filetype'} eq "ZIP") {
        	push (@nodefiles,"$r->{'filename'}.txt");
   		}

    } else {
		#####################################
		# Node stuff
		# Do node stuff, no routing etc just extract the data and make a report

		my $result = donode($r,$rid);

		if ($result->{'success'}) {
            $prep{'success'} = 1;
	    	$prep{'filename'} = $result->{'filename'};
	    	$prep{'md5'} = $result->{'md5'};
	    	$prep{'size'} = $result->{'size'};
			$prep{'rid'}=$r->{'metadata'}{'rid'};
		} else {
	    	$prep{'message'} = $result->{'message'};
	    	$prep{'error'} = $result->{'message'};
			return(\%prep);
		}

		my $reportfilename=mkreport(0,$r,\%prep);
		mkjlog($r, \%prep);

		if ($prep{'filetype'} eq "ZIP") {
            if ($reportfilename) {
				push(@nodefiles,"$result->{'filename'}.txt");
            }
		}
		push(@nodefiles,$r->{'metadata'}{'tempfile'});
    }

    # Now we have the file(s) we want to rtn to the client, lets zip or merge into a single p cap as requested
    if ($multifile) {
    	wlog("DEBUG: Merging pcap files");
		if ( $prep{'filetype'} eq "PCAP" ) {
            # @nodefiles is a list of pcaps w/o a path, we need then with a path to merge
            # @mergefiles is a temp array of just that.
            my @mergefiles=();
            wlog("DEBUG: Merge file list is..");
            foreach (@nodefiles) {
				push(@mergefiles, "$config{'SAVEDIR'}/$_");
            }

            my $mergecmd="$config{'MERGECAP'} -w $config{'SAVEDIR'}/$r->{'metadata'}{'tempfile'}.pcap @mergefiles";
            wlog("DEBUG: Merge cmd is $mergecmd\n") if $debug;
                unless (system($mergecmd)) {
                    wlog("DEBUG: Created $config{'SAVEDIR'}/$r->{'metadata'}{'tempfile'}.pcap") if $debug;
                    $prep{'filename'}="$r->{'metadata'}{'tempfile'}.pcap";
                    $prep{'success'} = 1;
                    $prep{'md5'} = getmd5("$config{'SAVEDIR'}/$r->{'metadata'}{'tempfile'}.pcap");
                    wlog("DEBUG: MD5 of merged pcap file is $prep{'md5'}");
                } else {
                    wlog("PREP: ERROR merging $config{'SAVEDIR'}/$r->{'metadata'}{'tempfile'}.pcap");
                    $prep{'message'} = "PREP : Unable to proxy-merge the pcap files.";
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

            if ($zip->writeToFileNamed("$config{'SAVEDIR'}/$r->{'metadata'}{'tempfile'}.zip") !=AZ_OK ) {
				wlog("PREP: ERROR: Problem creating $config{'SAVEDIR'}/$r->{'tempfile'}.zip");
            } else {
				wlog("PREP: Created $config{'SAVEDIR'}/$r->{'metadata'}{'tempfile'}.zip") if $debug;
				$prep{'filename'}="$r->{'metadata'}{'tempfile'}.zip";
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
	my $r=shift;
	my @cmdargs=();
	my $bpf;
	my %result=(
		filename => 0,
        success => 0,
        message => 0,
        md5 => 0,
        size => 0,
        error => 0,
	);
	my $debug=wantdebug();

	wlog "DEBUG: Doing Node action \n" if $debug;
	# Unless we have been given a real bpf from the user, make our own
	unless ($r->{'bpf'}{'val'} ) {
            $bpf=OFPC::Common::mkBPF($r);
	} else {
            $bpf=$r->{'bpf'}{'val'};
	}

    # If for some reason we have failed to get a BPF, lets return an error
	unless ($bpf) {
            $result{'message'} = "Insufficient constraints for request (Null or invalid BPF)";
            $result{'error'} = "Insufficient constraints for request (Null or invalid BPF)";
            wlog("NODE : Request: $r->{'metadata'}{'rid'} " . $result{'message'});
            return(\%result);
	}

	wlog("NODE : Request: $r->{'metadata'}{'rid'} User: $r->{'user'}{'val'} Action: $r->{'action'}{'val'} BPF: $bpf");

	# Do we have a single timestamp or pair of them?
	# Single= event sometime in the middle of a session
	# stime/etime = a search time window to look for data over
	my @pcaproster=();
	if ( $r->{'stime'}{'val'} && $r->{'etime'}{'val'} ) {
			wlog("NODE : Getting a bunch of pcap files between $r->{'stime'}{'val'} (" . localtime($r->{'stime'}{'val'}) .
				") and $r->{'etime'}{'val'} (" . localtime($r->{'etime'}{'val'}) . ")") if $debug;
            @pcaproster=bufferRange($r->{'stime'}{'val'}, $r->{'etime'}{'val'});

	} else  {
			wlog("NODE : Getting a bunch of pcap files around timestamp $r->{'timestamp'}{'val'} (" . localtime($r->{'timestamp'}{'val'}) . ")");
            # Event, single look over roster
            @pcaproster=findBuffers($r->{'timestamp'}{'val'}, 1);
	}

	# If we don't get any pcap files, there is no point in doExtract
	my $pcapcount=@pcaproster;
	unless ($pcapcount) {
            $result{'message'} = "No suitable pcap files found in $config{'BUFFER_PATH'}";
            return(\%result);
	}

	wlog("DEBUG: Final PCAP roster ($pcapcount files in total) for extract is: @pcaproster\n") if $debug;

	(my $filename, my $size, my $md5, my $err) = doExtract($bpf,\@pcaproster,$r->{'metadata'}{'tempfile'});

	if ($filename) {
            $result{'filename'} = $filename;
            $result{'success'} = 1;
	    	$result{'message'} = "Success";
	    	$result{'md5'} = $md5;
	    	$result{'size'} = $size;
	    	$result{'err'} = $err;
	    wlog("NODE : Request: $r->{'metadata'}{'rid'} User: $r->{'user'}{'val'} Result: $filename, $size, $md5");
	} else {
	    	$result{'err'} = $err;
            wlog("NODE : Request: $r->{'metadata'}{'rid'} User: $r->{'user'}{'val'} Result: Problem performing doExtract $err.");
	}

	# Create extraction Metadata file

	unless ( open METADATA , '>', "$config{'SAVEDIR'}/$filename.txt" ) {
            $result{'message'} = "Unable to open Metadata file  $config{'SAVEDIR'}/$r->{'metadata'}{'tempfile'}.txt for writing";
            wlog("PREP: ERROR: $result{'message'}");
            return(\%result);
	}

	print METADATA "Extract Report - OpenFPC Node $r->{'device'}{'val'}\n";
	print METADATA "User: $r->{'user'}{'val'}\n" .
            "Filename: $r->{'filename'}{'val'}\n" .
            "MD5: $md5\n" .
            "Size: $size\n" .
            "User comment: $r->{'comment'}{'val'}\n" .
            "Time: $r->{'rtime'}{'val'}\n";
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
        ($nodehost, $nodeport) = split(/:/, $nodevalue);
        wlog("ROUTE: Routing equest to node: $device");
    } else {
        wlog("ROUTE: No openfpc-route entry found for $device in routing table\n");
        return(0,0);
    }

    unless ($nodehost and $nodeport) {
        wlog("ROUTE: ERROR: Unable to pass route line $nodevalue");
        return(0,0);
    } else {
        return($nodehost,$nodeport);
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
	my $debug=wantdebug;

	wlog("DEBUG: Buffer Range mode") if $debug;

	# Find first and last files/timestamps in case we are performing an out-of-bounds search
	wlog("Getting First file in buffer range") if $debug;
	my @starttmp=findBuffers($starttimestamp,0);
	if (defined $starttmp[0] ) {
		$startfile=$starttmp[0];
	} else {
		wlog("DEBUG: starttimestamp to early for buffer range. Using first file $bufferinfo->{'firstfilename'}\n");
		$startfile=$bufferinfo->{'firstfilename'};
	}

	wlog("Getting Last file in buffer range") if $debug;
	my @endtmp=findBuffers($endtimestamp,0);
	if (defined $endtmp[0] ) {
		$endfile=$endtmp[0];
	} else {
		wlog("DEBUG: Endfile to late for buffer range. Using last file $bufferinfo->{'lastfilename'}\n");
		$endfile=$bufferinfo->{'lastfilename'};
	}
	wlog("DEBUG: Starting search in file $startfile ($starttimestamp)\n") if ($debug);
	wlog("DEBUG: Ending   search in file $endfile ($endtimestamp)\n") if ($debug);
	# Look for files between startfile and endfile if startfile is not the same as endfile

	my @pcaptemp = `ls -rt $config{'BUFFER_PATH'}/openfpc-$config{'NODENAME'}.pcap.*`;

	unless ($startfile eq $endfile) {
        foreach(@pcaptemp) {
	        chomp $_;
		if ($_ =~ /$startfile/) {
			$include=1;
		} elsif ($_ =~ /$endfile/ ) {
			$include=0;
			push(@pcaps,$_); # catch the last file before unset of include
		}
	        push(@pcaps,$_) if ($include);
			if ($debug) {
				wlog("VDBEUG: +Include $_ \n") if ($include);
				wlog("VDEBUG: -Include $_ \n") unless ($include);
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
	my $debug=wantdebug();
	wlog("DEBUG: WARNING vdebug not enabled to inspect pcap filename selection\n") if ($debug and not $vdebug);

	my @pcaptemp = `ls -rt $config{'BUFFER_PATH'}/openfpc-$config{'NODENAME'}.pcap.*`;
        foreach(@pcaptemp) {
                chomp $_;
                push(@pcaps,$_);
        }

        wlog("DEBUG: Request is to look in $numberOfFiles files each side of target timestamp ($targetTimeStamp) (" . localtime($targetTimeStamp) . ")\n") if $debug;

        $targetTimeStamp=$targetTimeStamp-0.5;                  # Remove risk of TARGET conflict with file timestamp.
        push(@timestampArray, $targetTimeStamp);                # Add target timestamp to an array of all file timestamps
        $timeHash{$targetTimeStamp} = "TARGET";                 # Method to identify our target timestamp in the hash
        wlog("DEBUG: Requested timestamp is $targetTimeStamp " . localtime $targetTimeStamp) if $debug;

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
                foreach (sort {$a <=> $b} @timestampArray) {
                        print "DEBUG  $count";
                        print " - $_ $timeHash{$_}\n";
                        $count++;
                }
                print "-------------------------------------\n";
        }

        $location=0;
        $count=0;
        foreach (sort {$a <=> $b} @timestampArray){                 # Sort our array of timetsamps (including
            $count++;                               # our target timestamp)
            print " + $count - $_ $timeHash{$_}\n" if ($debug and $vdebug);
            if ( "$timeHash{$_}" eq "TARGET" ) {
            	# Problem is that the we're not finding the first file correctly when looking for something too old.
                wlog("DEBUG: Got TARGET match of $_ in array location $count\n") if $debug;
                if ($count == 1) {
                   	wlog("DEBUG: Count ($count), is already at the lowest location in the file list. won't go any lower.");
                   	$location=$count;
                } else {
	                $location=$count - 1;
                }
                if ( defined $timeHash{$timestampArray[$location]} ) {
	                if ($vdebug) {
                        wlog("DEBUG: Pcap file at previous to TARGET is in location $location -> filename $timeHash{$timestampArray[$location]} \n");
    	        	}
    	        	last;
    	        } else {
    	            wlog("ERROR: Something went wrong, there should be a file at location $location), but there isn't one defined.");
    	        }
            } elsif ( "$_" == "$targetTimeStamp" ) {     # If the timestamp of the pcap file is identical to the timestamp
                $location=$count;               	 # we are looking for (corner case), store its place
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
            wlog(" - Target PCAP filename is $timeHash{$timestampArray[$location]} : $tts ( " . localtime($tts) . ")\n") if $tts;
        }

        # Find what pcap files are eachway of target timestamp
        my $precount=$numberOfFiles;
        my $postcount=$numberOfFiles;
        wlog("DEBUG: Precount value (number of files before target is  :$precount") if $debug;
        wlog("DEBUG: Postcount value (number of files before target is :$postcount") if $debug;
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
        my $pnum=@TARGET_PCAPS;
        wlog("DEBUG: Returning of a total of $pnum pcap files") if $vdebug;
        return(@TARGET_PCAPS);
}


=head2 doExtract
	Performs an  "extraction" of session(s) from pacp(s) using tcpdump.
	Pass me a bpf, list of pcaps(ref), and a filename and it returns a filesize and a MD5 of the extracted file
	e.g.
	doExtract($bpf, \@array_of_files, $requested_filename);
	return($filename,$filesize,$md5,$errormessage);

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
	my $err;
    my @outputpcaps=();
    my $debug=1;

    wlog("DEBUG: Doing Extraction with BPF $bpf into tempdir $tempdir\n") if ($debug);

	# Test if tcpdump can read files, it's a common problem with apparmor - here we can catch it with a nice error
	# Check that file isn't 0 bytes long before testing tcpdump read
	@filelist = validatepcaplist(@filelist);

    foreach (@filelist){
		my $splitstring="$config{'NODENAME'}\.pcap\.";
        (my $pcappath, my $pcapid)=split(/$splitstring/, $_);
        chomp $_;
        my $filename="$tempdir/$mergefile-$pcapid.pcap";
        push(@outputpcaps,$filename);
        wlog("DBEUG: doExtract: Extracting from $_");
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

	return($mergefile,$filesize,$md5,$err);
}

=head2 mkjlog
	Create a JSON text log of the extract
=cut

sub mkjlog{
	my $r=shift;
	my $q=shift;
	my %jlog=(
		request => $r,
		result => $q,
		);
	my $log_json=encode_json(\%jlog);
	my $filename="$config{'SAVEDIR'}/$r->{'metadata'}{'rid'}.json";

	if (open JSON , '>', $filename)  {
		print JSON $log_json;
		close(JSON);
		wlog("JSON : Created log JSON log for session $r->{'metadata'}{'rid'}");
	} else {
		wlog("MKLOG: ERROR: Unable to open JSON log file $filename for writing");
	}
}

=head2 mkreport
	Create a text report about the extraction.
=cut

sub mkreport{
	my $filename=shift;	# Filename to create
	my $r=shift;	# HashRef to request data.
	my $extract=shift;	# Details about the extract process
	my $bpf=0;

	unless ($r->{'bpf'}{'val'}) {
		$bpf=OFPC::Common::mkBPF($r);
	} else {
		$bpf=$r->{'bpf'}{'val'};
	}

	$filename="$config{'SAVEDIR'}/$r->{'metadata'}{'rid'}.txt" unless ($filename);

	if (open REPORT , '>', $filename)  {

       		print REPORT "###################################\nOFPC Extract report\n" .
			"User: $r->{'user'}{'val'}\n" .
      		       	"User comment: $r->{'comment'}{'val'}\n"  .
			"-----------------------------------\n" .
			"Event Type    : $r->{'logtype'}{'val'}\n" .
			"Event Log     : $r->{'logline'}{'val'}\n" .
			"Request time  : $r->{'rtime'}{'val'}\n" .
			"Comment       : $r->{'comment'}{'val'}\n" .
			"---------------------------\n" ;
		print REPORT "Timestamp     : $r->{'timestamp'}{'val'} (" . localtime($r->{'timestamp'}{'val'}) . ")\n" if $r->{'timestamp'}{'val'};
		print REPORT "Start Time    : $r->{'stime'}{'val'} (" . localtime($r->{'stime'}{'val'}) . ")\n" if $r->{'stime'}{'val'};
		print REPORT "End Time      : $r->{'etime'}{'val'} (" . localtime($r->{'etime'}{'val'}) . ")\n" if $r->{'etime'}{'val'};
		print REPORT "BPF Used      : $bpf\n";

		print REPORT "Filename:     : $extract->{'filename'} \n" .
			"Size          : $extract->{'size'} \n" .
			"MD5           : $extract->{'md5'} \n" .
			"Feedback      : $extract->{'message'}\n" .
			"---------------------------\n";
		close(REPORT);
		return($filename);
	} else {
		wlog("PREP: ERROR: Unable to open MetaFile $config{'SAVEDIR'}/$r->{'tempfile'}{'val'}.txt for writing");
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
    my $r=shift;
    my %result=(
		message => "None",
		success => 0,
		filename => 0,
		size => 0,
		md5 => 0,
    );
    my $r2=OFPC::Request::mkreqv2();
    my $nodesock = IO::Socket::INET->new(
                                PeerAddr => $r->{'metadata'}{'nodehost'},
                                PeerPort => $r->{'metadata'}{'nodeport'},
                                Proto => 'tcp',
                                );

    unless ($nodesock) {
		wlog("PROXY: Unable to open socket to node $r->{'metadata'}{'nodehost'}:$r->{'metadata'}{'nodeport'}");
		$result{'message'} = "Node: $config{'NODENAME'} unable to connect to node $r->{'metadata'}{'nodehost'}:$r->{'metadata'}{'nodeport'}";
		$result{'success'} = 0;
		return(\%result);
    }
    # This is an openfpc-proxy request, we don't want the user to control what file we will
    # write on the proxy. Create our own tempfile.
    $r2->{'filename'}{'val'}="M-$r->{'metadata'}{'nodehost'}-$r->{'metadata'}{'nodeport'}-" . time() . "-" . $r->{'metadata'}{'rid'};
    $r2->{'user'}{'val'} = $r->{'metadata'}{'nodeuser'};
    $r2->{'password'}{'val'} = $r->{'metadata'}{'nodepass'};
    $r2->{'savedir'}{'val'} = $config{'SAVEDIR'};
    $r2->{'action'}{'val'} = "fetch";
    # pre-make the bpf at the proxy for use on all nodes
    if ($r->{'bpf'}{'val'}) {
    	# BPF specified in request, no need to build one
    	$r2->{'bpf'}{'val'} = $r->{'bpf'}{'val'};	
    } else {
    	# Make a bpf from the session IDs passed
	    $r2->{'bpf'}{'val'} = OFPC::Common::mkBPF($r);
    }


    %result=OFPC::Request::request($nodesock,$r2);

    # Return the name of the file that we have been passed by the node
    if ($result{'success'} == 1) {
		wlog("PROXY: Success: Received file $result{'filename'} MD5: $result{'md5'} Size $result{'size'} from $r->{'device'}{'val'} ($r->{'metadata'}{'nodehost'})\n");
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
    my $debug=wantdebug();
    my $userlist=OFPC::Common::readpasswd("$config{'PASSWD'}") or die("Problem processing users file $config{'PASSWD'}");
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

	                    if ($userlist->{$state{'user'}}) {	# If we have a user account for this user

	        	        my $clen=20; #Length of challenge to send
	                        my $challenge="";
	                        for (1..$clen) {
	                            $challenge="$challenge" . int(rand(99));
	                        }

	                        wlog("DEBUG: $client_ip: Sending challenge: $challenge\n") if $debug;
	                        print $client "CHALLENGE: $challenge\n";

	                        wlog("DEBUG: $client_ip: Waiting for response to challenge\n") if $debug;
	                        # Expected response to the challenge is a hex MD5 of the challenge appended with the users password hash
	                        $state{'response'}=md5_hex("$challenge$userlist->{$state{'user'}}{'pass'}");

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
		                # wlog("DEBUG: $client_ip: REQ -> $reqcmd\n") if $debug;

		                my $request=OFPC::Common::decoderequest($reqcmd);
		                if ($request->{'valid'}{'val'} == 1) {	# Valid request then...
							# Generate a rid (request ID for this.... request!).
							# Unless action is something we need to wait for, lets close connection

							my $position=$queue->pending();

							if ("$request->{'action'}{'val'}" eq "store") {
									wlog("REQ: Action Store");
		                            # Create a tempfilename for this store request
		                            $request->{'metadata'}{'tempfile'}=$request->{'metadata'}{'rid'} . ".pcap";
		                            print $client "FILENAME: $request->{'metadata'}{'tempfile'}\n";
		                           	print $client "RID: $request->{'metadata'}{'rid'}\n";
		                            $queue->enqueue($request);

		                            #Say thanks and disconnect
		                            wlog("DEBUG: $client_ip: RID: $request->{'metadata'}{'rid'}: Queue action requested. Position $position. Disconnecting\n");
		                            print $client "QUEUED: $position\n";
		                            shutdown($client,2);

							} elsif ($request->{'action'}{'val'} eq "fetch") {
									wlog("REQ: Action Fetch");
		                            # Create a tempfilename for this store request
		                            $request->{'metadata'}{'tempfile'}=time() . "-" . $request->{'metadata'}{'rid'} . ".pcap";
					    			wlog("COMMS: $client_ip: RID: $request->{'metadata'}{'rid'} Fetch Request OK, sending RID\n");
					    			print $client "RID: $request->{'metadata'}{'rid'}\n";

					    			# Prep result of the request for delivery (route/extract/compress etc etc)
		                            my $prep = OFPC::Common::prepfile($request);
		                            my $xferfile=$prep->{'filename'};

		                            if ($prep->{'success'}) {
										wlog("COMMS: $request->{'metadata'}{'rid'} $client_ip Sending File:$config{'SAVEDIR'}/$xferfile MD5: $prep->{'md5'}");
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

										wlog("COMMS: $client_ip Request: $request->{'metadata'}{'rid'} : Transfer complete") if $debug;

										# unless configured to keep it, delete the pcap file from
										# this queue instance

										unless ($config{'KEEPFILES'}) {
		                                    wlog("COMMS: $client_ip Request: $request->{'metadata'}{'rid'} : Cleaning up.") if $debug;
		                                    unlink("$config{'SAVEDIR'}/$xferfile") or
		                                    	wlog("COMMS: ERROR: $client_ip Request: $request->{'metadata'}{'rid'} : Unable to unlink $config{'SAVEDIR'}/$xferfile");
										}
		                            } else {
										print $client "ERROR: $prep->{'message'}\n";
			                        	shutdown($client,2);	# CLose client
		                            }

							} elsif ($request->{'action'}{'val'} eq "status") {
		    	                wlog("Received status request");

			                    my $s=OFPC::Common::getstatus($request);
			                    my $sj = encode_json($s);
		        	            print $client "STATUS: $sj";
		    	                wlog("Status response sent to client") if $debug;
			        	        shutdown($client,2);
							} elsif ($request->{'action'}{'val'} eq "apikey") {
								wlog("Received request for user API key for user $state{'user'}");
								print $client "MESSAGE: $userlist->{$state{'user'}}{'apikey'}\n";
								wlog("Sent API key back for user $state{'user'}: $userlist->{$state{'user'}}{'apikey'}");
								shutdown($client,2);
							} elsif ($request->{'action'}{'val'} eq "search") {
								wlog("COMMS: $client_ip: RID: $request->{'metadata'}{'rid'} Search Request\n");
		                        wlog("COMMS: $client_ip: RID: $request->{'metadata'}{'rid'} Start time=$request->{'stime'}{'val'} End time=$request->{'etime'}{'val'}");

		                        (my $t)=OFPC::CXDB::cx_search($request);
		                        unless ($t->{'error'}) {
		                        	my $tj=encode_json($t);
									print $client "TABLE:\n";
									wlog("DEBUG: Sending table JSON....\n") if ($debug);
									print $client $tj . "\n";

		                            print $client "\n";
		                        } else {
									print $client "ERROR: $t->{'error'}\n";
		                        }
		                        wlog("COMMS: $client_ip: RID: $request->{'metadata'}{'rid'} Table Sent. Closing connection\n");
			                    shutdown($client,2);
							} else {
								wlog("Error: Unknown action $request->{'action'}{'val'}");
							}
		                } else {
							wlog("COMMS: $client_ip: BAD request $request->{'msg'}{'val'}");
							print $client "ERROR: $request->{'msg'}{'val'}\n";
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
	     	    print $client "ERROR: Request format OFPC-v1 is deprecated and no longer compatible with OFPC. Please update your OpenFPC Client\n" ;
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

            wlog("RUNQ : Found request: $request->{'metadata'}{'rid'} Queue length: $qlen");
            wlog("RUNQ : Request: $request->{'metadata'}{'rid'} User: $request->{'user'} Found in queue:");

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
                    wlog("RUNQ : NODE: Request: $request->{'metadata'}{'rid'} Success. File: $result->{'filename'} $result->{'size'} now cached on NODE in $config{'SAVEDIR'}");
                    $pcaps{$request->{'metadata'}{'rid'}}=$result->{'filename'};
                } else {
                    wlog("RUNQ: NODE: Request: $request->{'metadata'}{'rid'} Result: Failed, $result->{'message'}.");
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
	my $debug=wantdebug();
	my %rt;						# Route table

    wlog("ROUTE: Reading route data from file: $config{'NODEROUTE'}");
    if ( -f $config{'NODEROUTE'}) {
			open NODEROUTE, '<', $config{'NODEROUTE'} or die "Unable to open node route file $config{'NODEROUTE'} \n";
			wlog("ROUTE: Reading route file $config{'NODEROUTE'}");
			while(<NODEROUTE>) {
		    chomp $_;
	    	unless ($_ =~ /^[# \$\n]/) {
	    		if ( (my $key, my $value) = split /=/, $_ ) {
		   	 		$route{$key} = $value;
					wlog("ROUTE: Adding route for $key as $value");
					($rt{$key}{'ip'}, $rt{$key}{'port'}) = split/:/, $value;
					$rt{$key}{'name'} = $key;
	    		}
	    	}
			}
    	close NODEROUTE;
    } else {
			wlog("Error, unable to find routes file $config{'NODEROUTE'}");
			die("No route file defined\n");
    }
    return(\%rt);
}

=head readpasswd
    Read in the passwd file, and return a hash of the contents
    - Leon Ward 2011

    Expects: $filename
    Returns: $hash_ref of passwords and API keys by user
=cut

sub readpasswd{
    my $pf=shift;
	my $debug=wantdebug();
   	my $h=();
    open my $fh, '<', $pf or die "ERROR: Unable to open passwd file $pf $!\n";
    while(<$fh>) {
        chomp;
        if ( $_ =~ m/^[a-zA-Z]/) {
            (my $s, my $u, my $p, my $k) = split /=/, $_;
            if ($s eq "SHA1") {
                wlog("DEBUG: Adding user \"$u\"") if $debug;
                $h->{$u}{'apikey'} = $k if $k;
                $h->{$u}{'pass'} = $p if $p;
            }
        }
    }
    close $fh;
    return($h);
}

=head logdie
	Log a message and then die with the same error
=cut

sub logdie{
	my $msg=shift;
	wlog($msg);
	die($msg);
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
			if ($value[0]){
		    $config{$key} = join '=', @value;
        	}
        }
    }

    my @ce=();

    # Check that important things are all set in the config
    if ( $config{'PROXY'}) {
    	# Proxy device
    	@ce=('PROXY_DB_USER',
    		'PROXY_DB_PASS',
    		'PROXY_DB_HOST',
    		'PROXY_DB_NAME',
    		);

    } else {
    	# normal node
    	@ce=('DESCRIPTION',
    		'BUFFER_PATH',
    		);
    }

    foreach (@ce) {
    	logdie("ERROR: $_ is not defined in configuration") unless $config{$_};
    }

    return(%config);
}

1;
