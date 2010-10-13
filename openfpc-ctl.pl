#!/usr/bin/perl
# The master control program for starting and stopping OpenFPC instances.
# Work in progress.... Dont use me yet....
# -Leon Ward  2010

use strict;
use warnings;
use Getopt::Long;
use Switch;
use Data::Dumper;

my $version=0.2;
my $conf_dir="/etc/openfpc";

my ($action,$quiet,$usertype,$verbose);
my $type=0;
my $thing=0;
my $instance=0;
my %configs=();						# Hash of all configs in $CONF_DIR;
my @daemonsNode=("openfpc-daemonlogger", 		# Daemons we want to start in OpenFPC Node mode
		"openfpc-queued",
		"openfpc-cxtracker".
		"openfpc-cx2db" );

my @daemonsProxy=("openfpc-queued"); 			# Daemons we want to start in OpenFPC proxy mode

=head2 getType
	Unless a user has specified if we are taking action on a daemon, or a configuration, this function will try to autodetect.
	The only real risk of failing to detect is if someone stupidly names a configuration the same name as a daemon
	e.g. NODENAME="openfpc-daemonlogger"

	Expects string
	Returns a hash ...

	(	type => "config",
	  	instance => "instance" ,
		filename => "/etc/openfpc/config.filename",
	)
 
=cut
sub getType{
	
	#my $thing=shift; 			# What type of thing is $thing
	my %result=( 	type => 0 ,
			instance => 0,
			filename => 0, 
		);
	my @daemons=(	"openfpc-queued",
			"openfpc-daemonlogger",
			"openfpc-cxtracker",
			"openfpc-cx2db");
	
	# Check if thing is one of our known daemons
	foreach(@daemonsNode) {
		if ( $_ eq $thing ) {
			$result{'type'} = "daemon";
			$result{'filename'} = "/etc/init.d/" . $thing;	
			return(\%result);
		}
	}

	# Check if thing is one of our config files
	if ( exists $configs{$thing} ) {
		$result{'type'} = "instance";
		$result{'instance'} = "$thing";
	}

	# Check if thing is a node-name in any of the config files.
	foreach (keys(%configs)) {
		my $filename=$_;
		if ( $thing eq $configs{$_}{'NODENAME'} ) {
			$result{'type'} = "instance";
			$result{'filename'} = "$filename";
			return(\%result);
		}
	}


	# We don't know what it is.
	return(\%result);	
}

=head2 getInstanceByDaemon
	Get a list of instances that this daemon needs to be started for.
	returns an array of instances (config filenames)
=cut

sub getInstanceByDaemon{
	my $daemon=shift;
	my @instances=();

	foreach my $conf (keys(%configs)) {
		if ( $configs{$conf}{'OFPC_ENABLED'} eq "y") {
			if ($configs{$conf}{'PROXY'} == 1) {
				# Enabled Proxy
				if ( grep $_ eq $daemon, @daemonsProxy ) {
					push(@instances, $conf);
				}
			} elsif ($configs{$conf}{'PROXY'} == 0 ) {
				if ( grep $_ eq $daemon, @daemonsNode ) {
					push(@instances, $conf);
				}
			}
		}
	}
	return(@instances);
}


=head2 getDaemonsByInstance
	Return a list of daemons we need to start for a config files
=cut

sub getDaemonsByInstance{
	my $instance=shift;
	my @daemons=();
	
	print "Proxt in instance $instance is $configs{$instance}{'PROXY'} \n";
	
	if ($configs{$instance}{'PROXY'} == 1 ) {
		return(@daemonsProxy);
	} elsif ($configs{$instance}{'PROXY'} == 0  ) {
		return(@daemonsNode);
	} else {
		die("Unknown Proxy config for instance: $instance\n");
	}
}


GetOptions (    'a|action=s' => \$action,		# Action to take
		'v|verbose' => \$verbose,		# Verbose
		't|thing=s' => \$thing,			# The thing we want to take action on
		'i|instance=s' => \$instance,		# The instance of thing
		'q|quiet' => \$quiet,
);

# Read in a hash of all configs on the system

opendir(my $dh, $conf_dir) || die("Unable to open config dir $conf_dir\n");
while(my $file=readdir $dh) {
	open FILE, '<', "$conf_dir/$file" or die "Unable to open config file $conf_dir/$file $!";
	while(my $line=<FILE>) {
        	chomp $line;
	        if ( $line =~ m/^[a-zA-Z]/) {
	                (my $key, my @value) = split /=/, $line;
	                unless ($key eq "USER") {
	                        $configs{$file}{$key} = join '=', @value;
                	}    
        	}
	}
	close(FILE);

}
closedir($dh);

#print Dumper %configs;


# Check if we need to start in the context of a daemon, or an instance.
# Get the type of the thing the user wants to start/stop

my $ofpc=getType($thing);
print "Filename is $ofpc->{'filename'} \n Type is $ofpc->{'type'} \n" if $verbose;

if ( $ofpc->{'type'} eq "daemon" ) {
		my @instances=getInstanceByDaemon($thing);
		print "Instances for $thing:\n";
		foreach (@instances){
			print "- $_\n";
		}
} elsif ( $ofpc->{'type'} eq "instance" ) {
		my @daemons=getDaemonsByInstance($ofpc->{'filename'});
		print "Daemons for instance $thing\n";
		foreach (@daemons) {
			print "- $_\n";
		}
} else {
	die("Dont know what this is");
}

# Check action is valid
#switch($action) {
#	case "start" {
#		# Decide on what to start
#		# itype = type if insance (daemon/node/config)
#
#		my $type=getType($thing);
#		print "Filename is $type->{'filename'} \n Type is $type->{'type'} \n" if $verbose;
#	} 
#	case "stop" {
#
#	} 
#	case "restart" {
#
#	}
#	case "status" {
#
#	}
#	else {
#		die "Error: Unknown action $action\n";
#	}
#}
