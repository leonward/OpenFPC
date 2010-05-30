#!/usr/bin/perl

# ofpc-queued.pl - Leon Ward leon@rm-rf.co.uk

use strict;
use warnings;
use threads;
use threads::shared;
use IO::Select;
use IO::Socket;
use Digest::MD5(qw(md5_hex));

my @CONFIG_FILES=("/etc/openfpc/openpfc-queued.conf","/opt/openfpc/openfpc-queued.conf","openfpc-queued.conf");
my $openfpcver="0.1a";

my ($queuelen,$debug,$verbose,$rid,$CONFIG_FILE,%config,%users);
my @queue : shared =1; @queue=();  # Shared queue array

$debug=1;
my $TCPPORT=4242;


if ($debug) { $verbose=1;}

sub listener{
	my ($read_set,$request_s,$request,$sock);
	print "Starting listener thread\n" if ($debug);
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
                                sysread $rh, $request, 2048,0; # TODO Input validation on len
                                if($request) {
					# OFPC-protocol
					my ($Rofpcver, $Ruser) = split(/\|\|/, $request);
					print "L- OFPCVER=$Rofpcver \nL- User = $Ruser\n"; 
					if ($Rofpcver eq "OFPC-v1") {
						print "L- V1.1 - User: $Ruser\n" if ($debug);
						if ($users{$Ruser}) {
							print "FOUND USER $Ruser\n";
							my $slen=10;
							my $challenge=0;
							for (1..$slen) {
								$challenge="$challenge" . int(rand(99));
							}
							print $rh "CHALLENGE||$challenge\n";
							#my $expResp="$challenge$users{$Ruser}";
							my $expResp=md5_hex("$challenge$users{$Ruser}");
							my $resp;
							sysread $rh, $resp, 128,0;
							chomp $resp;
							if ("$resp" eq "$expResp") {
								print "L- Pass Okay\n";
							} else {
								print "L- Pass Bad\n";
							}
						}
					}		

					#push(@queue,$request);
                        	} else {
                                	$read_set->remove($rh);
                                	close($rh);
				}
                        }
                }
        }
}

sub processEvent{
	# Process the data we have picked up
	my $erid=shift; 	# The rid value for this extract 
	my $request=shift;
	
	print "P- $erid Processing event rid:$erid\n" if ($verbose);
}

############ Start here ############

# Decide what config file to read
foreach (@CONFIG_FILES) {
        if ( -f $_ ) { 
                if ($verbose) {
                        print "* Reading config file $_\n";
                }
                $CONFIG_FILE=$_;
                last;
        }
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
			$users{$value[0]} = $value[1];
		}
        }
}
close $config;



my $ipthread = threads->create(\&listener);
$ipthread->detach();
#$ipthread->join();





while (1) {
	my $qlen=@queue;
	if ($debug) {
		print "Q- Waiting (debug mode)...\n"; 
		sleep(1);
	}
	if ($qlen >= 1) {
		print "Q- $qlen Found extract request in queue\n" if ($verbose);
		print "Q- $qlen Qlen: $qlen\n" if ($verbose);
		$rid++;
		my $request=shift(@queue);
		print "Q- $qlen Calling extract for rid $rid\n";
		processEvent($rid,$request);
	}
}


