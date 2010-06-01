#!/usr/bin/perl -I /opt/openfpc/ .

# ofpc-queued.pl - Leon Ward leon@rm-rf.co.uk

use strict;
use warnings;
use threads;
use threads::shared;
use IO::Select;
use IO::Socket;
use Digest::MD5(qw(md5_hex));
use Getopt::Long;
use ofpcParse;
use Data::Dumper;

my $openfpcver="0.1a";

my ($queuelen,$debug,$verbose,$rid,$CONFIG_FILE,%config,%userlist);
my @queue : shared =1; @queue=();  	# Shared queue array
my @rqueue : shared =1; @rqueue=();  	# Shared retry queue array (for extracts that have failed)

$debug=1;
my $TCPPORT=4242;
if ($debug) { $verbose=1;}

sub decoderequest($){
	# Take a rawrequest from a user and return a ref to a hash of event data
	my $rawrequest=shift;
	my %request=();	
	($request{'user'},$request{'action'},$request{'device'},$request{'filename'},$request{'location'},$request{'logtype'},$request{'logline'}) = split(/\|\|/, $rawrequest) ;
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
	return(\%request);
}

sub parselog{
	# Revieve a logline, and return a ref to a hash that contains its data
	my $logline=shift;
	if ($debug) { print "   Parsing a logline :$logline\n"; }
 	my %eventdata = ();     # Hash of decoded event

        # Work through a list of file-parsers until we get a hit        
	while (1) {
        	%eventdata=ofpcParse::SF49IPS($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=ofpcParse::Exim4($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=ofpcParse::SnortSyslog($logline); if ($eventdata{'parsed'} ) { last; }
                %eventdata=ofpcParse::SnortFast($logline); if ($eventdata{'parsed'} ) { last; }
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

	return(\%eventdata);
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
                                sysread $rh, $protover, 20, 0; 	# TODO Input validation on len
                                if ($protover) { 		# Get protocol version from client
					chomp($protover);
					print "-L Got version $protover\n" if ($debug);

					if ($protover eq "OFPC-v1") { 	# V1 event - In case this changes over time maintain compatibility
						my ($rawrequest, %request, $reqh);
						print "-L Using OFPC-v1 protocol\n" if ($debug);
						print $rh "OFPC-v1 OK\n";
						sysread $rh, $rawrequest, 1024,0;
						chomp $rawrequest;
						$reqh=decoderequest($rawrequest);
						#($request{'user'},$request{'action'},$request{'device'},$request{'filename'},$request{'location'},$request{'logtype'},$request{'logline'}) = split(/\|\|/, $rawrequest);
						# Check we have a sane request before doing anything
						# put above in an unless
						#print "Got line $request\n";

						if ($userlist{$reqh->{'user'}}) {
							if ($debug) { print "-L User: $reqh->{'user'} OK\n"; }
							my $slen=10;
							my $challenge="";
							for (1..$slen) {
								$challenge="$challenge" . int(rand(99));
							}

							print $rh "CHALLENGE||$challenge\n";
							#my $expResp="$challenge$userlist{$user}";
							my $expResp=md5_hex("$challenge$userlist{$reqh->{'user'}}");
							my $resp;
							sysread $rh, $resp, 128,0;
							chomp $resp;

							if ($debug) {
								print "-L Expected resp: -$expResp-\n";
								print "-L Real resp    : -$resp-\n";
							}

							# Check response hash
							if ( "$resp" eq "$expResp" ) {
								print "-L Pass Okay\n" if ($debug);
								print $rh "Pass OK\n";
								# Good to process
								(my $result, my $message) = preprocessEventV1($reqh,$rh);
								print "Result is $result, message is $message\n";
								print $rh "$result||$message\n";

								# This is ugly, but threads::shared cant yet share nested references. 
								# So instead of adding a ref to our request onto the queue array ill
								# put the raw data onto it we got from the client. It's be tested so 
								# we know it makes sense.

								push(@queue,$rawrequest);
							} else {
								print "-L Pass Bad\n" if ($debug);
								print $rh "Pass Bad $resp\n";
							}

							$read_set->remove($rh);
							close($rh);
						} else {
							print "-L User: $request{'user'} -> invalid - Hangup\n" if ($debug);
							print $rh "FAIL||Invalid user $request{'user'}\n";
							$read_set->remove($rh);
							close($rh);
						}
					}		

                        	} else {
                                	$read_set->remove($rh);
                                	close($rh);
				}
                        }
                }
        }
}

sub runqueue{
	# Process the data we have picked up and found in the queue
	# I expect to be given the request itself (rather than a href to the decoded request due to 
	# limitations with threads::shared and a request ID

	my $request=shift;
	my $erid=shift; 	# The rid value for this extract 
	my $extractcmd;
	my $cmdargs;		# Command args for slave extract
	
	print "Q- $erid Processing event rid:$erid\n" if ($verbose);
	print "Q- $erid \n" if ($verbose);

	my $reqh=decoderequest($request);
	unless ($reqh) { return(0,"Unable to decode request in runqueue"); 
	my $eventh=parselog($reqh->{'logline'});
	unless ($eventh) { return(0,"Unable to parse log line in runqueue");
	
	# If we are the MASTER push this to a slave device
	# If we are a slave, lets to the work
	
	if ($config{'MASTER'}) {
		print "Q-* Master NOT DONE YET\n";
	} else { # End of master code
		print "Q- Slave device performing extraction\n";

		if ($verbose) {
			$extractcmd="ofpc-extract.pl --debug -a \"$reqh->{'logline'}\"";
			print "Extract command is $extractcmd\n";
		} else {
			$extractcmd="ofpc-extract.pl -a \"$reqh->{'logline'}\"";
		}
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
			print "C- Adding user:$value[0]: Pass:$value[1]\n"; 
			$userlist{$value[0]} = $value[1];
		}
        }
}
close $config;

if ($verbose) {
	if ($config{'MASTER'}) { 
		print "*  Running in MASTER mode\n"; 
	} else {
		print "*  Running in SLAVE mode\n"; 
	}
}

my $ipthread = threads->create(\&listener);
$ipthread->detach();
#$ipthread->join();

while (1) {
	sleep(1);			# Pause between polls of queues
	my $qlen=@queue;		# Length of extract queue
	my $rqlen=@rqueue;		# Length of retry queue
	if ($qlen >= 1) {
		my %request=();
		print "Q- $qlen Found extract request in queue\n" if ($verbose);
		print "Q- $qlen Qlen: $qlen\n" if ($verbose);
		$rid++;
		my $request=shift(@queue);
		print "Q- $qlen Calling extract for rid $rid $request\n";
		my ($result,$message) = runqueue($request,$rid);
		if ($verbose) {
			print "Q- Result: $result\nQ-  Message: $message\n";	
		}
	}
}


