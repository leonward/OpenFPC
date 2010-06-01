#!/usr/bin/perl -I /opt/openfpc/ .

# ofpc-queued.pl - Leon Ward leon@rm-rf.co.uk
# TODO - Sort out dupe decodes
#        Add log file
#	 Check extraction result
#	 Add MD5/SHA1 of files
#	 Pass files back to master directly
#        Add master mode

use strict;
use warnings;
use threads;
use threads::shared;
use IO::Select;
use IO::Socket;
use Digest::MD5(qw(md5_hex));
use Getopt::Long;
use Data::Dumper;
use ofpcParse;

my $openfpcver="0.1a";

my ($queuelen,$debug,$verbose,$rid,$CONFIG_FILE,%config,%userlist);
my @queue : shared =1; @queue=();  	# Shared queue array
my @rqueue : shared =1; @rqueue=();  	# Shared retry queue array (for extracts that have failed)

my $daemon=0;
$debug=1;
$verbose=1;
my $TCPPORT=4242;
if ($debug) { $verbose=1;}

sub pipeHandler {
    my $sig = shift @_;
    print "SIGPIPE -> Bad client went away! $sig \n\n" if ($verbose);
}

$SIG{PIPE} = \&pipeHandler;


sub decoderequest($){
	# Take a rawrequest from a user and return a ref to a hash of event data
	my $rawrequest=shift;
	my %request=( 	user 	 => 	0,
			action 	 =>	0,
			device 	 =>	0,
			filename =>	0,
			locatoin =>	0,
			logtype  =>	0,
			logline  =>	0,
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

	if ($debug) { 
                print "-- Decoded Request --\n" .
                "   User: $request{'user'}\n" .
                "   Action: $request{'action'}\n" .
                "   Devide: $request{'device'}\n" .
                "   Filename: $request{'filename'}\n" .
                "   Location: $request{'location'}\n" .
                "   Type: $request{'logtype'}\n" .
                "   LogLine: $request{'logline'}\n";
        }

	return(\%request,"Okay");
}

sub parselog{
	# Revieve a logline, and return a ref to a hash that contains its data
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
                print "PARSE ---Decoded Event---\n" .
                       "   Type: $eventdata{'type'}\n" .
                       "   Timestamp: $eventdata{'timestamp'} (" . localtime($eventdata{'timestamp'}) . ")\n" .
                       "   SIP: $eventdata{'sip'}\n" .
                       "   DIP: $eventdata{'dip'}\n" .
                       "   SPT: $eventdata{'spt'}\n" .
                       "   DPT: $eventdata{'dpt'}\n" .
                       "   Protocol: $eventdata{'proto'}\n" .
                       "   Message: $eventdata{'msg'}\n" ;
        }

	return(\%eventdata,);
}

sub preprocessEventV1{
	# Pre-process the request
	# Make sure the evene request makes sense

	my %request=%{$_[0]};	
	my $request_ref=\%request;	# Ref to my request hash

	my %eventdata = ();	# Hash of decoded event

        # Work through a list of file-parsers until we get a hit        
        while (1) {
                %eventdata=ofpcParse::SF49IPS($request{'logline'}); if ($eventdata{'parsed'} ) { last; }
                %eventdata=ofpcParse::Exim4($request{'logline'}); if ($eventdata{'parsed'} ) { last; }
                %eventdata=ofpcParse::SnortSyslog($request{'logline'}); if ($eventdata{'parsed'} ) { last; }
                %eventdata=ofpcParse::SnortFast($request{'logline'}); if ($eventdata{'parsed'} ) { last; }
		return(0,"Unable to parse log message");
        }

        if ($debug) {
                print " ---Decoded Event---\n" .
                        "   Type: $eventdata{'type'}\n" .
                        "   Timestamp: $eventdata{'timestamp'} (" . localtime($eventdata{'timestamp'}) . ")\n" .
                        "   SIP: $eventdata{'sip'}\n" .
                        "   DIP: $eventdata{'dip'}\n" .
                        "   SPT: $eventdata{'spt'}\n" .
                        "   DPT: $eventdata{'dpt'}\n" .
                        "   Protocol: $eventdata{'proto'}\n" .
                        "   Message: $eventdata{'msg'}\n" ;
        }

	return(1,"Okay");
}

sub ofpcv1{
	# V1 of communication
	my $handle=shift;
	my ($rawrequest, %request);
	print "v1 Using OFPC-v1 protocol\n" if ($debug);
	print $handle "OFPC-v1 OK\n";
	#$rawrequest=<$handle>;
	sysread $handle, $rawrequest, 1024,0;
	chomp $rawrequest;
	
	# Check we have a sane request before doing anything
	# put above in an unless

	my ($reqh,$message)=decoderequest($rawrequest);
	if ($reqh) {	
		if ($userlist{$reqh->{'user'}}) {
			# Valid user
			print "v1 User: $reqh->{'user'} OK\n" if ($debug);
			my $slen=10;
			my $challenge="";
			for (1..$slen) {
				$challenge="$challenge" . int(rand(99));
			}
			print "v1 Sending challenge: $challenge\n" if ($debug);
			print $handle "CHALLENGE $challenge\n";
			print "Waiting for response to challenge\n" if ($debug);
			#my $expResp="$challenge$userlist{$reqh->{'user'}}";
			my $expResp=md5_hex("$challenge$userlist{$reqh->{'user'}}");
			my $resp;
			#$resp=<$handle>;
			sysread $handle, $resp, 128,0;
			chomp $resp;

			if ($debug) {
				print "v1 Expected resp: -$expResp-\n";
				print "v1 Real resp    : -$resp-\n";
			}

			# Check response hash
			if ( "$resp" eq "$expResp" ) {
				print "v1 Pass Okay\n" if ($debug);
				print $handle "PASS OK\n";
				wlog("LOGIN $reqh->{'user'} OK");
				# Good to process
				(my $result, my $message) = preprocessEventV1($reqh,$handle);

				# This is ugly, but threads::shared cant yet share nested references. 
				# So instead of adding a ref to our request onto the queue array ill
				# put the raw data onto it we got from the client. It's be tested so 
				# we know it makes sense.

				if ($result) {
					print "v1 PreprocessEvent OK : Result $result : Message: $message\n" if ($debug);
					push(@queue,$rawrequest);
					wlog("ADDED TO QUEUE: $reqh->{'user'} $rawrequest");
					return(1,"OK");
				} else {
					if ($verbose) {
						print "v1 PreprocessEvent FAIL : Result $result : Message: $message\n" if ($debug);
						wlog("BAD REQUES: $reqh->{'user'} $message : $rawrequest");
					}
					return(0,"BAD REQUEST||$message");
				}
			} else { # BAD PASS
				print "v1 Pass Bad\n" if ($debug);
				return(0,"PASS BAD");
			}

		} else { # Invalid user
			print "v1 User: $request{'user'} -> invalid - Hangup\n" if ($debug);
			return(0,"BAD USER");
		}
	} else { # Bad request
		print "V1 Bad request\n" if ($debug);
		return(0,"BAD ofpc-v1 REQUEST: $message");
	}
}

sub wlog{
	my $logdata=shift;
	chomp $logdata;
	my $gmtime=gmtime();
	unless ($daemon) {
		print "LOG: $gmtime GMT: $logdata\n";
	}
}


sub listener{
	my ($read_set,$request_s,$request,$sock,$protover);
	print "*  Starting listener thread\n" if ($debug);
	$sock = IO::Socket::INET->new(
                                LocalPort => $TCPPORT,
                                Proto => 'tcp',
                                Listen => '10',
                                Reuse => 1,
                                );
        unless ($sock) { die("Problem creating socket!"); }

        $read_set=new IO::Select();
        $read_set->add($sock);
        while (1) {  # Sit and wait for connections and requests to queue
                my ($rh_set) = IO::Select->select($read_set, undef, undef, 0); 
                foreach my $rh (@$rh_set) { # For each read handle in the set of all handles
                        if ($rh == $sock) {
                                my $ns = $rh->accept();
                                $read_set->add($ns);
                        } else {
				my $client_ip=$rh->peerhost;		
				wlog("$client_ip Connected");
                                #$protover=<$rh>;
				my $hello;
				print "Waiting for hello\n";
				sysread $rh, $hello, 20, 0; 	# HELLO 
				print "Got $hello Sending banner: \n";
				print $rh "OFPC READY\n";
				print "Waiting for client version\n";
				sysread $rh, $protover, 20, 0; 	# TODO Input validation on len
				print "got ver $protover\n";
                                if ($protover) { 		# Get protocol version from client
					chomp($protover);
					chomp($protover);
					print "-L Got version ->$protover<-\n" if ($debug);
					if ($protover eq "OFPC-v1") { 	# V1 event - In case this changes over time maintain compatibility
						my ($result, $message) = ofpcv1($rh);
						if ($result) {
								my $qlen=@queue;
								print $rh "OK||QUEUE $qlen\n";
						} else {
							print $rh "$message\n";
						}
					}		
                        	} else {
					print $rh "BAD PROTOCOL\n"; 
				}
                                $read_set->remove($rh);
                                close($rh);
                        }
                }
        }
	print "At end of while1\n";
}

sub runqueue{
	# Process the data we have picked up and found in the queue
	# I expect to be given the request itself (rather than a href to the decoded request due to 
	# limitations with threads::shared and a request ID

	my $request=shift;
	my $erid=shift; 	# The rid value for this extract 
	my $extractcmd;
	my @cmdargs;		# Command args for slave extract
	
	print "R- $erid Processing event rid:$erid\n" if ($verbose);
	print "R- $erid \n" if ($verbose);

	my ($reqh,$message)=decoderequest($request);
	unless ($reqh) { return(0,"Unable to decode request in runqueue -> $message"); }
	my $eventh=parselog($reqh->{'logline'});
	unless ($eventh) { return(0,"Unable to parse log line in runqueue"); }
	
	# If we are the MASTER push this to a slave device
	# If we are a slave, lets to the work
	
	if ($config{'MASTER'}) {
		print "R- $erid * Master NOT DONE YET\n";
	} else { # End of master code
		print "R- $erid Slave device performing extraction\n";
		# Depending on the log type, we may have all constraints, or possibly only a couple
		push(@cmdargs,"./ofpc-extract.pl -m a");
	#	if ($debug) { push (@cmdargs,"--debug"); }
		if ($debug) { push (@cmdargs,"--http"); }
		if ($eventh->{'sip'}) { push (@cmdargs,"--src-addr $eventh->{'sip'}") ; }
		if ($eventh->{'dip'}) { push (@cmdargs,"--dst-addr $eventh->{'dip'}") ; }
		if ($eventh->{'spt'}) { push (@cmdargs,"--src-port $eventh->{'spt'}") ; }
		if ($eventh->{'dpt'}) { push (@cmdargs,"--dst-port $eventh->{'dpt'}") ; }
		if ($eventh->{'proto'}) { push (@cmdargs,"--proto $eventh->{'proto'}") ; }
		if ($eventh->{'timestamp'}) { push (@cmdargs,"--timestamp $eventh->{'timestamp'}") ; }
		#if ($reqh->{'location'}) { push (@cmdargs,$reqh->{'location'}) ; }
		if ($reqh->{'filename'}) { push (@cmdargs,"--write $reqh->{'filename'}") ; }

		foreach(@cmdargs) {
			$extractcmd=$extractcmd . "$_ ";
		}

		print "Extract command is $extractcmd\n" if ($verbose);
		my $result=`$extractcmd`;
		if ($debug)  {
			print "Result : $result\n"
		}
		return(1,"FILENAME: $result");
		
	} # End of slave code
	# We shouldn't get here unless something has broken
	return(0,"Unknown problem while trying to run queue on $erid")
}



############ Start here ############

# Some config defaults
$config{'MASTER'}=0;

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

my $ipthread = threads->create(\&listener);
$ipthread->detach();
#$ipthread->join();

while (1) {
	sleep(1);			# Pause between polls of queues
	if ($debug) { 
#		print "Waiting.\n" ;
	} 
	my $qlen=@queue;		# Length of extract queue
	my $rqlen=@rqueue;		# Length of retry queue
	if ($qlen >= 1) {
		my %request=();
		print "Q- $qlen Found extract request in queue\n" if ($debug);
		print "Q- $qlen Qlen: $qlen\n" if ($debug);
		$rid++;
		my $request=shift(@queue);
		wlog("Current queue length: $qlen");
		wlog("Request: $rid Found in queue: $request");
		my ($result,$message) = runqueue($request,$rid);
		wlog("Request: $rid Result: $result  Message: $message");	
	}

}

print "-\n\n-------------WTF?------- \n\n\n";

