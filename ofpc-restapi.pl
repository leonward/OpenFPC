#!/usr/bin/perl -I.
use strict;
use warnings;
use OFPC::Request;
use Dancer;
use Dancer::Plugin::REST;
use DateTime::TimeZone;
use IO::Socket::INET;
use URI::Escape;
use Data::UUID;
use Switch;

# Set logging to console
set logger => "console";
set log => "debug";
set log => "core";
set warnings => 1;
set serializer => 'JSON';


my %std=(
        message => "Error",
        fail => 0,
);

my %config=(
	server => '192.168.42.10',
	port => '4242',
	passwdfile => '/tmp/test.passwd',
);

=head2 readusers
	Reads an openfpc user file and returns a hash of user, password, and APIkeys
=cut

sub readusers{
	my %users=();
	my $file=shift;
	info "Reading user data from file $file";
	if ( -f $file ) {
       	open FILE, '<', "$file" or die "Unable to open openfpc-password users file $file $!";
       	my $ucount=0;
       	while(my $line=<FILE>) {
            chomp $line;
		    if ( $line =~ m/^SHA1/) {
		    	$ucount++;
	 			(my $key, my @value) = split /=/, $line;
				# Make a blank users hash for this user to make sure we have all of the values defined.
				$users{$value[0]}{'user'} = $value[0];
				$users{$value[0]}{'password'} = 0;
				$users{$value[0]}{'apikey'} = 0;
				#$users{$value[0]} = $value[1];

				# Now assign the values.
				$users{$value[0]}{'password'} = $value[1] if defined $value[1];
				$users{$value[0]}{'apikey'} = $value[2] if defined $value[2];
				unless (defined $value[2]) {
					debug "WARNING: one or more users doesn't have an API key defined: $users{$value[0]}{'user'}";
				}
        	}	   
    	}
		info "$ucount users defined in openfpc-password file";
		die("Error: No users defined in openfpc-password file") unless $ucount; 
    	close(FILE);
	} else {
		die("Error: openfpc-password file doesn't exist: $file\n");
	}

	# Check that there are some users defined:
	return(\%users);
}

sub apikeys{
	my $file=shift;
	my $users=readusers($file);
	my %ak=();
	debug "User dump:";
	debug $users;

	foreach my $u (keys %$users) {
		if (defined $users->{$u}{'apikey'}) {
			debug "Found API key for user $u : $users->{$u}{'apikey'}";
			$ak{$users->{$u}{'apikey'}}{'user'} = $u;
			$ak{$users->{$u}{'apikey'}}{'password'} = $users->{$u}{'password'};
		}
	}
	debug \%ak;	
	return(\%ak);
}

sub doit{
	my $r=shift;
	my $sock = IO::Socket::INET->new(
		PeerAddr => $config{'server'},
        PeerPort => $config{'port'},
        Proto => 'tcp',
    );  
    my %q=(
    	error => '0',
    	);
	unless ($sock) { 
		$q{'error'} = "Unable to create socket to server $config{'server'} on TCP:$config{'port'}\n"; 
		return(\%q);
	} else {
		info "Connected to OpenFPC queue daemon: $config{'server'}\n";
	}

	debug "Making request to $config{'server'} : $config{'port'}";
	%q=OFPC::Request::request($sock,$r);	
	debug "Response from Queue daemon";
	debug \%q;

	return(\%q);
}

sub checkauth{
	my $key=shift;
	my $akdb=shift;
	my %q = (
		auth => 0,
		user => 0,
		password => 0,
		error => 0,
		);

	if (defined $akdb->{$key}) {
		info "Authorized apikey for user $akdb->{$key}{'user'} : $key\n";
		$q{'auth'} = 1;
		$q{'user'} = $akdb->{$key}{'user'};
	} else {
		info "Unauthorized apikey used. Doesn't match to any user: $key\n";
		$q{'error'} = "Forbidden. Invalid API key $key";
	}
	return(\%q);
}

sub checkinput{
	debug "Performing API input validation";
	my $f=shift;
	my %q = (
		error => 0,
		hint => 0,
	);
	unless (params->{'apikey'}) {
		warn "No API key included in request";
		$q{'error'} = "API key required";
		return(\%q)
	} else {
		warn "Okay";
	}
	#switch($f){
#
#		case 'fetch' {
#
#		}

#	}
	return(\%q);
}

my $akdb=apikeys($config{'passwdfile'});

checkauth('41855202-788B-11E4-8482-8D0352865C70', $akdb);

get '/status' => sub {
	info "Received Status request";
	my $r=OFPC::Request::mkreqv2;
	$r->{'action'}{'val'} = "status";
	$r->{'user'}{'val'} = 'tester';
	$r->{'password'}{'val'} = 'testing';
	$r->{'password'}{'val'} = OFPC::Request::mkhash($r->{'user'}{'val'},$r->{'password'}{'val'});

    my $q=doit($r);
	debug "RESULT-------------";
	return $q;
};

get '/fetch' => sub {
	info "Processing fetch request";

	my ($bpf, $sip, $dip, $stime, $etime, $timestamp)=0;
	$bpf=params->{'bpf'} if params->{'bpf'};
	my $r=OFPC::Request::mkreqv2;

	my $e = checkinput('fetch');
	return $e if $e->{'error'};

	#my $auth=checkauth(params->{'apikey'});
	#return $auth->{'error'} unless $auth->{'auth'};

	$r->{'action'}{'val'} = "fetch";
	$r->{'user'}{'val'} = 'tester';
	$r->{'password'}{'val'} = 'testing';
	$r->{'password'}{'val'} = OFPC::Request::mkhash($r->{'user'}{'val'},$r->{'password'}{'val'});

	debug "Escaped BPF is $bpf";
	my $u_bpf=uri_unescape($bpf);
	debug "Unescaped BPF is $u_bpf";
	$r->{'bpf'}{'val'} = $u_bpf;

	my $q=doit($r);
	return($q);
};

 any qr{.*} => sub {
 	my %q=(
 		error => 1,
 		success => 0,
 		errortext => "Invalid function, no such path",
	);
	return(\%q);
};

dance;
