#!/usr/bin/perl
use strict;
use warnings;
use Switch;
use threads;
use threads::shared;
use Thread::Queue;
use IO::Socket;
use Digest::MD5(qw(md5_hex));
use Getopt::Long;
use Data::Dumper;
use ofpcParse;

my $openfpcver="0.1a";

my ($queuelen,$debug,$verbose,$rid,$CONFIG_FILE,%config,%userlist);
#my @queue : shared =1; @queue=();       # Shared queue array
#my @rqueue : shared =1; @rqueue=();     # Shared retry queue array (for extracts that have failed)
my $queue = Thread::Queue->new();	# Queue shared over all threads
my $mrid : shared =1; $mrid=1;	# Master request counter. Quick way to identify  requests
my $daemon=0;
#$debug=1;
$verbose=1;
my $TCPPORT=4242;
if ($debug) { $verbose=1;}

sub getrequestid{
	$mrid++;	
	return($mrid);
}

sub parselog{
        # Recieve a logline, and return a ref to a hash that contains its data if valid
        my $logline=shift;
        if ($debug) { print "   Parsing a logline :$logline\n"; }
        my %eventdata = ();     # Hash of decoded event

        # Work through a list of file-parsers until we get a hit        
        while (1) {
                %eventdata=ofpcParse::OFPC1Event($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=ofpcParse::SF49IPS($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=ofpcParse::Exim4($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=ofpcParse::SnortSyslog($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=ofpcParse::SnortFast($logline); if ($eventdata{'parsed'} ) { last; }
                return(0,"Unable to parse log message");
        }
 
        if ($debug) {
                print "   ---Decoded Event---\n" .
                       "   Type: $eventdata{'type'}\n" .
                       "   Timestamp: $eventdata{'timestamp'} (" . localtime($eventdata{'timestamp'}) . ")\n" .
                       "   SIP: $eventdata{'sip'}\n" .
                       "   DIP: $eventdata{'dip'}\n" .
                       "   SPT: $eventdata{'spt'}\n" .
                       "   DPT: $eventdata{'dpt'}\n" .
                       "   Protocol: $eventdata{'proto'}\n" .
                       "   Message: $eventdata{'msg'}\n" ;
        }

        return(\%eventdata,"Success");
}

sub decoderequest($){
        # Take a rawrequest from a user and return a ref to a hash of event data
        my $rawrequest=shift;
        my %request=(   user     =>     0,
                        action   =>     0,
			rid	 =>	0,
                        device   =>     0,
                        filename =>     0,
                        locatoin =>     0,
                        logtype  =>     0,
                        logline  =>     0,
			sip	=>	0,
			dip	=>	0,
			proto	=>	0,
			spt	=>	0,
			dpt	=>	0,
			msg	=>	0,
			timestamp =>	0,
			stime	=>	0,
			etime	=>	0,
        );
        my @requestarray = split(/\|\|/, $rawrequest);

        my $argnum=@requestarray;
        unless ($argnum == 7 ) {
                if ($debug) {
                        print "-D  Bad request, only $argnum args. Expected 7\n";
                }
                return(0,"Expected 7 args, got $argnum");
        }
        ($request{'user'},$request{'action'},$request{'device'},$request{'filename'},$request{'location'},$request{'logtype'},$request{'logline'}) = split(/\|\|/, $rawrequest);
        

	# Check logline is valid
	my ($eventdata, $error)=parselog($request{'logline'});
	unless ($eventdata) {
		wlog("ERROR: Cannot parse logline-> $error");
		return(0,"Invalid action $request{'action'}");
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

	if ($debug) {
                print "   ---Decoded Request---\n" .
                "   User	: $request{'user'}\n" .
		"   RID		: $request{'rid'}\n".
                "   Action: 	$request{'action'}\n" .
                "   Devide: 	$request{'device'}\n" .
                "   Filename: 	$request{'filename'}\n" .
                "   Location: 	$request{'location'}\n" .
                "   Type: 	$request{'logtype'}\n" .
                "   LogLine: 	$request{'logline'}\n" .
		"   SIP:		$request{'sip'}\n" .
		"   DIP:		$request{'dip'}\n" .
		"   Proto:	$request{'proto'}\n".
		"   SPT:		$request{'spt'}\n" .
		"   DPT:		$request{'dpt'}\n" .
		"   MSG:		$request{'msg'}\n" .
		"   Timestamp	$request{'timestamp'}\n" .
		"   StartTime	$request{'stime'}\n" .
		"   EndTime	$request{'etime'}\n" ;
        }

	# Check action: Valid actions are:
	# fetch 	Fetch pcap and return to client/server
	# save		Store session and return success/fail message to requestor
	# queue		Queue session for extracion, and disconnect
	# replay	Replay traffic (FUTURE)

	$request{'action'} = lc $request{'action'};
	$request{'rid'} = getrequestid();

	if (($request{'action'} eq "fetch" ) or ($request{'action'} eq "save" ) or ($request{'action'} eq "replay") or ($request{'action'} eq "queue")) {
		wlog("DECODE: Recieved valid action $request{'action'}");
        	return(\%request,"Okay");
	} else {
		wlog("DECODE: Recieved invalid action $request{'action'}");
		return(0,"Invalid action $request{'action'}");
	}
}

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
	    	print "$client_ip -> Got data $buf :\n" if ($debug);
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
					}
				} else {
					wlog("COMMS: $client_ip: Bad USER: request $buf. Sending ERROR");
					print $client "ERROR: Bad user request\n";
				}

			} case /RESPONSE/ {
				print "DEBUG $client_ip: Got RESPONSE\n" if ($debug);
				if ($buf =~ /RESPONSE:*\s*(.*)/) {
					my $response=$1;
					if ($debug) {
                                		print "DEBUG: $client_ip: Expected resp: $state{'response'}-\n";
                                		print "DEBUG: $client_ip: Real resp    : $response\n";
                        		}
                        		# Check response hash
                        		if ( $response eq $state{'response'} ) {	
						wlog("COMMS: $client_ip: Pass Okay");
						$state{'response'}=0;		# Reset the response hash. Don't know why but it sounds like a good idea to me
						$state{'auth'}=1;		# Mark as authed
						print $client "AUTH OK\n";
					} else {
						print "DEBUG: $client_ip: Pass bad\n";
						print $client_ip "AUTH FAIL\n";
					}
				} else {
					print "DEBUG $client_ip: Bad USER: request $buf\n " if ($debug);
					print $client "ERROR: Bad password request\n";
				}

			} case /ERROR/ {
                                print "DEBUG $client_ip: Got error closing connection\n";
                                shutdown($client,2);

			} case /^REQ/ {	
				my $reqcmd;
				# OFPC request. Made up of ACTION||
				if ($buf =~ /REQ:\s*(.*)/) {
					$reqcmd=$1;
					print "DEBUG: $client_ip: REQ -> $reqcmd\n" if ($debug);
					my ($request,$error)=decoderequest($reqcmd);
					unless ($request == 0) {
						# Generate a rid (request ID for this.... request!).
						# Unless action is something we need to wait for, lets close connection
						my $position=$queue->pending();
						if ("$request->{'action'}" eq "queue") {
							$queue->enqueue($request);
							#Say thanks and disconnect
							print "DEBUG: $client_ip: RID: $request->{'rid'}: Queue actin requested -> disconnecting\n" if ($debug);
							print $client "QUEUED: $position\n";
							shutdown($client,2);
							
						} else {
							$queue->enqueue($request);
							wlog("COMMS: $client_ip: RID: $request->{'rid'} Request OK -> WAIT!\n");
							print $client "WAIT: $position\n";
						}
					} else {
						wlog("COMMS: $client_ip: BAD request $error");
						print $client "ERROR $error\n";
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
                        
sub wlog{
        my $logdata=shift;
        chomp $logdata;
        my $gmtime=gmtime();
        unless ($daemon) {
                print "LOG: $gmtime GMT: $logdata\n";
        }
}



sub domaster{
	my $request=shift;
	die("Not done yet");
}

sub doslave{
	my $extractcmd;
	my $request=shift;
	my @cmdargs=();
	wlog("SLAVE: Request: $request->{'rid'} Performing slave action");

        # Depending on the log type, we may have all constraints, or possibly only a couple
        push(@cmdargs,"./ofpc-extract.pl -m a");
        push (@cmdargs,"--ofpc");
#        if ($debug) { push (@cmdargs,"--debug"); }
        if ($request->{'sip'}) { push (@cmdargs,"--src-addr $request->{'sip'}") ; } 
        if ($request->{'dip'}) { push (@cmdargs,"--dst-addr $request->{'dip'}") ; } 
        if ($request->{'spt'}) { push (@cmdargs,"--src-port $request->{'spt'}") ; } 
        if ($request->{'dpt'}) { push (@cmdargs,"--dst-port $request->{'dpt'}") ; } 
        if ($request->{'proto'}) { push (@cmdargs,"--proto $request->{'proto'}") ; } 
        if ($request->{'timestamp'}) { push (@cmdargs,"--timestamp $request->{'timestamp'}") ; } 
        if ($request->{'filename'}) { push (@cmdargs,"--write $request->{'filename'}") ; } 

        foreach(@cmdargs) {
 	       $extractcmd=$extractcmd . "$_ ";
        }   

        print "DEBUG: Extract command is $extractcmd\n" if ($debug);
        my $result=`$extractcmd`;
        if ($debug)  {
	        print "Result : $result\n"
        }   
        return(1,"FILENAME: $result");
}

#
sub runq {
	while (1) {
        	sleep(1);                       # Pause between polls of queues
        	if ($debug) { 
#               	print "Waiting.\n" ;
        	}
        	my $qlen=$queue->pending();     # Length of extract queue
        	if ($qlen >= 1) {
			my $request=$queue->dequeue();
                	wlog("QUEUE: Found request : Queue length: $qlen");
                	wlog("QUEUE Request: $request->{'rid'} User: $request->{'user'} Found in queue:");
			if ($config{'MASTER'}) {
				my ($result,$message)=domaster($request,$rid);
                		wlog("QUEUE: Request: $request->{'rid'} Result: $result  Message: $message");    
			} else {
				my ($result,$message) = doslave($request,$rid);
				if ($result) {
                			wlog("QUEUE: Request: $request->{'rid'} Result: Success: Filename: $message");    
				} else {
                			wlog("QUEUE: Request: $request->{'rid'} Result: Failed: $message");    
				}
			}
        	}
	}
}


########### Start here ############



# Some config defaults
$config{'MASTER'}=0;
$config{'SAVEDIR'}="/tmp";

GetOptions (    'c|conf=s' => \$CONFIG_FILE,
                );

if ($verbose) {
        print "*  Reading config file $CONFIG_FILE\n";
}

unless ($CONFIG_FILE) { die "Unable to find a config file"; }
open my $config, '<', $CONFIG_FILE or die "Unable to open config file $CONFIG_FILE $!";
while(<$config>) {
        chomp;
        if ( $_ =~ m/^[a-zA-Z]/) {
                (my $key, my @value) = split /=/, $_;
                unless ($key eq "USER") {
                        $config{$key} = join '=', @value;
                } else {
                        print "C- Adding user:$value[0]: Pass:$value[1]\n" if ($verbose);
                        $userlist{$value[0]} = $value[1] ;
                }
        }
}
close $config;

if ($config{'MASTER'}) {
        wlog("Starting in MASTER mode");
} else {
        wlog("Starting in SLAVE mode");
}

# Start listener
print "*  Starting listener \n" if ($debug);
my $listenSocket = IO::Socket::INET->new(
                                LocalPort => $TCPPORT,
                                Proto => 'tcp',
                                Listen => '10',
                                Reuse => 1,
                                );
unless ($listenSocket) { die("Problem creating socket!"); }
threads->create("runq");

while (my $sock = $listenSocket->accept) {
	# set client socket to non blocking
	my $nonblocking = 1;
	ioctl($sock, 0x8004667e, \\$nonblocking);
	$sock->autoflush(1);
	my $client_ip=$sock->peerhost;
	wlog("Accepted new connection from $client_ip") ;

	# start new thread and listen on the socket
	threads->create("comms", $sock);
}

