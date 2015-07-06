package ofpcapi;

use Dancer2;
use strict;
use warnings;
use OFPC::Request;
use DateTime::TimeZone;
use IO::Socket::INET;
use URI::Escape;
use Data::UUID;
use Switch;
use POSIX qw(setsid);

set warnings => 1;
set serializer => 'JSON';

our $VERSION = '0.1';
my $api_version="1";
my $prefix="/api/$api_version";
my %std=(
        message => "Error",
        fail => 0,
);
my $daemon=1;
my $configfile=shift;
my %config=(
	ofpc_server => 'localhost',
	ofpc_port => 4242,
	ofpc_savedir => '/tmp/',
	ofpc_passwd => '/etc/openfpc/openfpc.passwd',
	pidpath => '/var/run/openfpc-restapi',
);    

=head2 readusers
	Reads an openfpc user file and returns a hash of user, password, and APIkeys
=cut

sub readusers{
	my %users=();
	my $file=shift;
	if ( -f $file ) {
       	open FILE, '<', "$file" or error "Unable to open openfpc-password users file $file $!";
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
				if ($value[2]) {
					$users{$value[0]}{'password'} = $value[1] if defined $value[1];
					$users{$value[0]}{'apikey'} = $value[2] if defined $value[2];
				} else {
					debug "User: $users{$value[0]}{'user'} has no API key defined!";
				}
        	}	   
    	}
		debug "$ucount users defined in openfpc-password file";
		die("Error: No users defined in openfpc-password file") unless $ucount; 
    	close(FILE);
	} else {
		die("Error: openfpc-password file doesn't exist: $file\n");
	}

	# Check that there are some users defined:
	return(\%users);
}

sub read_apikeys{
	my $file=shift;
	debug "Reading API keys from $file";
	my $users=readusers($file);
	my %ak=();

	foreach my $u (keys %$users) {
		if ($users->{$u}{'apikey'}) {
			debug "Found API key for user $u : $users->{$u}{'apikey'}";
			$ak{$users->{$u}{'apikey'}}{'user'} = $u;
			$ak{$users->{$u}{'apikey'}}{'password'} = $users->{$u}{'password'};
		}
	}
	return(\%ak);
}

sub doit{
	my $r=shift;
	my $sock = IO::Socket::INET->new(
		PeerAddr => $config{'ofpc_server'},
        PeerPort => $config{'ofpc_port'},
        Proto => 'tcp',
    );  
    my %q=(
    	error => '0',
    	);
    # Force the ofpc_savedir to a value that is configured for the RestAPI
    $r->{'savedir'}{'val'}="/tmp/mytmp";

	unless ($sock) { 
		$q{'error'} = "Internal error: Unable to create socket to the OpenFPC Queue daemon (ofpc_server). Check error log for details\n"; 
		error "Unable to create socket to $config{'ofpc_server'} on port $config{'ofpc_port'}";
		return(\%q);
	} else {
		debug "Connected to OpenFPC queue daemon: $config{'ofpc_server'}\n";
	}

	debug "Making request to $config{'ofpc_server'}:$config{'ofpc_port'}";
	%q=OFPC::Request::request($sock,$r);	

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
		die("No apikey hash passed to function") unless $akdb;
		die("No key passed to function") unless $key;

	if (defined $akdb->{$key}) {
		debug "Authorized apikey for user $akdb->{$key}{'user'} : $key\n";
		$q{'auth'} = 1;
		$q{'user'} = $akdb->{$key}{'user'};
		$q{'password'} = $akdb->{$key}{'password'};
	} else {
		info "Unauthorized apikey used. Doesn't match to any user. Key: $key\n";
		debug $akdb;
		$q{'error'} = "Forbidden. Invalid API key $key";
	}
	return(\%q);
}

=head2 checkinput
	Checks the params-> for the action type $f.
	Returns a hash ref of normalized output that can be used for the action $f
=cut 

sub checkinput{
	my $f=shift;
	my %q=();

	debug "Performing API input validation for $f action";

	unless (params->{'apikey'}) {
		info "No API key included in request";
		$q{'error'} = "API key required";
		return(\%q);
	} else {
		$q{'apikey'} = params->{'apikey'};
		unless ($q{'apikey'}=~/^[A-Za-z0-9-]+$/) {
				$q{'error'} = "Error. API key failed input validation";
				error $q{'error'};
				warn "APIkey failed input validation: Key tested was \"" . params->{'rid'} . "\"";
				return(\%q);
		}
	}

	if ($f eq "retrieve") {
		unless (params->{'rid'}) {
			debug "No rid specified";
			$q{'error'} = "No request ID set";
			return(\%q);
		} else {
			$q{'rid'} = params->{'rid'};
		}
	}

	if (($f eq "store") || ($f eq "fetch") || ($f eq "search")) {
		if (params->{'bpf'}) {
			$q{'bpf'} = uri_unescape(params->{'bpf'});

			unless ($q{'bpf'}=~/^[A-Za-z0-9 \.\[\]\(\)&=\/]+$/) {
				$q{'error'} = "Error. BPF failed input validation";
				error $q{'error'};
				return(\%q);
			}
			debug "Decoded BPF is $q{'bpf'}";
		}	


		if (params->{'sip'}) {
			$q{'sip'}=uri_unescape(params->{'sip'});
			unless ($q{'sip'} =~ m/^(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$/) {
				$q{'error'} = "Error. Source IP failed input validation. Only IPv4 is supported today.";
				error $q{'error'};
				return(\%q);
			}	
			debug "Decoded sip is $q{'sip'}";
		}

		if (params->{'dip'}) {
			$q{'dip'}=uri_unescape(params->{'dip'});
			unless ($q{'dip'} =~ m/^(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})$/) {
				$q{'error'} = "Error. Destination IP failed input validation. Only IPv4 is supported today.";
				error $q{'error'};
				return(\%q);
			}	
			debug "Decoded dip is $q{'dip'}";
		}

		if (params->{'spt'}) {
			$q{'spt'}=uri_unescape(params->{'spt'});
			unless ($q{'spt'} =~ m/^(\d{1,5})$/) {
				$q{'error'} = "Error. Source port failed input validation.";
				error $q{'error'};
				return(\%q);
			}	
			debug "Decoded source port is $q{'spt'}";
		}

		if (params->{'dpt'}) {
			$q{'dpt'}=uri_unescape(params->{'dpt'});
			unless ($q{'dpt'} =~ m/^(\d{1,5})$/) {
				$q{'error'} = "Error. Destination port failed input validation.";
				error $q{'error'};
				return(\%q);
			}	
			debug "Decoded destination port is $q{'dpt'}";
		}

		if (params->{'limit'}) {
			$q{'limit'}=uri_unescape(params->{'limit'});
			unless ($q{'limit'} =~ m/^(\d{1,5})$/) {
				$q{'error'} = "Error. Limit too large for search result";
				error $q{'error'};
				return(\%q);
			}	
			debug "Accepted limit as $q{'limit'}";
		}

		foreach ('stime', 'etime', 'timestamp') {
			if (params->{$_}) {
				$q{$_}=uri_unescape(params->{$_});
				unless ($q{$_}=~/^[A-Za-z0-9 :\.\[\]\(\)\/\-]+$/) {
					$q{'error'} = "Error. $_ failed input validation.";
					error $q{'error'};
					return(\%q);
				}	
				debug "Accepted $_ as $q{$_}";
			}
		}
	}
	return(\%q);
}


debug "Config: Reading Configuration:";
die "Error: No ofpc_server defined in config, can't start" unless (config->{'ofpc_server'});
die "Error: No ofpc_port defined in config, can't start" unless (config->{'ofpc_port'});
die "Error: No ofpc_passwd defined in config, can't start" unless (config->{'ofpc_passwd'});
die "Error: No ofpc_savedir defined in config, can't start" unless (config->{'ofpc_savedir'});

$config{'ofpc_server'} = config->{'ofpc_server'};
$config{'ofpc_port'} = config->{'ofpc_port'};
$config{'ofpc_passwd'} = config->{'ofpc_passwd'};
$config{'ofpc_savedir'} = config->{'ofpc_savedir'};

info "CONFIG: OpenFPC Server: " . $config{'ofpc_server'};
info "CONFIG: OpenFPC Port: " . $config{'ofpc_port'};
info "CONFIG: OpenFPC Password file: " . $config{'ofpc_passwd'};
info "CONFIG: OpenFPC Save Directory: " . $config{'ofpc_savedir'};


my $api_keys=read_apikeys($config{'ofpc_passwd'});

get '/api/1/status' => sub {
	info "Received Status request";

	my $r=OFPC::Request::mkreqv2;
	$r->{'action'}{'val'} = "status";

	my $e=checkinput($r->{'action'}{'val'});
	return $e if $e->{'error'};

	my $auth=checkauth(params->{'apikey'},$api_keys);
	return { error => $auth->{'error'}} unless $auth->{'auth'};

	$r->{'password'}{'val'} = $auth->{'password'};
	$r->{'user'}{'val'} = $auth->{'user'};

    my $q=doit($r);
	return $q;
};

get '/api/1/fetch' => sub {
	info "Received fetch request";

	my $r=OFPC::Request::mkreqv2;
	$r->{'action'}{'val'} = "fetch";

	my $e=checkinput($r->{'action'}{'val'});
	return $e if $e->{'error'};
	$r->{'sip'}{'val'} = $e->{'sip'};
	$r->{'dip'}{'val'} = $e->{'dip'};
	$r->{'dpt'}{'val'} = $e->{'dpt'};
	$r->{'spt'}{'val'} = $e->{'spt'};
	$r->{'bpf'}{'val'} = $e->{'bpf'};

	my $auth=checkauth(params->{'apikey'}, $api_keys);
	return { error => $auth->{'error'}} unless $auth->{'auth'};

	$r->{'user'}{'val'} = $auth->{'user'};
	$r->{'password'}{'val'} = $auth->{'password'};

	my $p=doit($r);
	if ($p->{'success'}) {
		if ( -f $p->{'filename'}) {
			debug "Sending pcap file back to client";
			return send_file( $p->{'filename'}, 
				content_type => 'application/vnd.tcpdump.pcap', 
				filename => $p->{'rid'} . ".pcap",
				system_path => 1);
			debug "Completed pcap download";
		} else {
			return { error => "Internal Error. Unable to find extracted file in pcap store" };
		}
	} else {
		return($p);	
	}
	return { error => "There was an error processing this request. Check log for more information"};
};

=head2 store
	Request the extraction of a pcap for later access when needed
=cut

get '/api/1/store' => sub {
	info "Received store request";

	my $r=OFPC::Request::mkreqv2;
	$r->{'action'}{'val'} = "store";

	my $e=checkinput($r->{'action'}{'val'});
	return $e if $e->{'error'};
	$r->{'sip'}{'val'} = $e->{'sip'};
	$r->{'dip'}{'val'} = $e->{'dip'};
	$r->{'dpt'}{'val'} = $e->{'dpt'};
	$r->{'spt'}{'val'} = $e->{'spt'};
	$r->{'bpf'}{'val'} = $e->{'bpf'};

	my $auth=checkauth(params->{'apikey'}, $api_keys);
	return { error => $auth->{'error'}} unless $auth->{'auth'};

	$r->{'user'}{'val'} = $auth->{'user'};
	$r->{'password'}{'val'} = $auth->{'password'};

	my $p=doit($r);
	if ($p->{'success'}) {
		debug "Store request successful";
		return ($p);
	} else {
		debug "Store request failed";
		return($p);	
	}
	return { error => "There was an error processing this request. Check log for more information"};
};

get '/api/1/search' => sub {
	info "Received search request";

	my $r=OFPC::Request::mkreqv2;
	$r->{'action'}{'val'} = "search";

	my $e=checkinput($r->{'action'}{'val'});
	return $e if $e->{'error'};
	$r->{'sip'}{'val'} = $e->{'sip'};
	$r->{'dip'}{'val'} = $e->{'dip'};
	$r->{'dpt'}{'val'} = $e->{'dpt'};
	$r->{'spt'}{'val'} = $e->{'spt'};
	$r->{'bpf'}{'val'} = $e->{'bpf'};
	$r->{'stime'}{'val'} = $e->{'stime'};
	$r->{'etime'}{'val'} = $e->{'etime'};
	$r->{'timestamp'}{'val'} = $e->{'timestamp'};
	$r->{'limit'}{'val'} = $e->{'limit'};

	my $auth=checkauth(params->{'apikey'}, $api_keys);
	return { error => $auth->{'error'}} unless $auth->{'auth'};

	$r->{'user'}{'val'} = $auth->{'user'};
	$r->{'password'}{'val'} = $auth->{'password'};

	my $p=doit($r);
	if ($p->{'success'}) {
		return ($p->{'table'});
	} else {
		debug "Search request failed";
		return { error => "There was an error processing this request. Check log for more information"};
	}
};


get '/api/1/retrieve' => sub {
	debug "Processing a retrieve request";
	my $rid=0;
	my $e=checkinput('retrieve');
	return $e if $e->{'error'};
	$rid=$e->{'rid'};
	
	my $auth=checkauth(params->{'apikey'}, $api_keys);
	return { error => $auth->{'error'}} unless $auth->{'auth'};

	my $file=$config{'ofpc_savedir'} . "/" . $rid . ".pcap";

	if ( -f $file ) {
		return send_file( $file, 
			content_type => 'application/vnd.tcpdump.pcap', 
			filename => $file,
			system_path => 1);
	} else {
		debug "Unable to retrieve file $file. File not found.";
		return { error => "Error: File not available in PCAP store. Either still in extraction queue, or something bad has happened. Please try later" };
	}
	return { error => "There was an error processing this request. Check log for more information"};
};



any qr{.*} => sub {
	debug "Invalid function specified in request. $_";
 	return { error => "Invalid request - No such function"}; 
};

dance;
;

true;
