#!/usr/bin/perl -I .
#########################################################################################
# Copyright (C) 2010 Leon Ward 
# setup-openfpc.pl - Part of the OpenFPC - (Full Packet Capture) project
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
use Getopt::Long;
use Data::Dumper;
use File::Copy;

# Confguration Defaults
my $debug=0;
my $file="/etc/openfpc/openfpc-default.conf";		# The name of the output config file
my @configfiles=("/etc/openfpc/openfpc-node.conf",
		"/etc/openfpc/openfpc-proxy.conf",
		"/etc/openfpc/openfpc-default.conf", 
		"/etc/openfpc/openfpc.conf", 
		"./openfpc.conf");		# List if config files to use in order.
my (%userlist, %oldconfig, %question,%validation,%cmdargs,@qlist);

# Some system defaults. If there isn't a config files to read for current values, lets give the user a 
# hint to take something sensible.

my %config=( 
		INSTALL_DIR => "/opt/openfpc/",
		NODENAME => "Unnamed",
		GUIUSER => "gui",
                OFPCUSER => "root",  
                saveconfig => "./myopenfpc.conf",
		SAVEDIR => "/tmp",
		VERBOSE => "1",
		OFPC_PORT => "4242",
		PROXY => 0,
		BUFFER_PATH => "/var/tmp/openfpc",
	 	FILE_SIZE => "1G",
	 #	FILE_SIZE => "10M",
		DISK_SPACE => "50",
		SESSION_DB_NAME => "openfpc",
		SESSION_DB_USER => "openfpc",
		SESSION_DB_PASS => "openfpc",
		SESSION_DIR => "/var/tmp/openfpc_session",	
		DONE => "n",
		INTERFACE => "eth1",
		DAEMONLOGGER => "daemonlogger",
		CXTRACKER => "cxtracker",
		ENABLE_IP_V6 => "0",
		ENABLE_SESSION => "0",
		OFPC_Q_PID => "/tmp/openfpc-queued.pid",
		NODEROUTE => "0",
                );  

# Rather than dupe questions for different operation modes and setup styles, these are a list of questions to ask for node/simple, node/advanced, and in the future proxy/simple, proxy/advanced.

# For version 0.2, I've disabled the GUI to get a release out while fixing some of the problems there.
# So i'm not asking GUI questions, commented out. - Leon

my @sessionq=(
	"SESSION_DIR",
	"SESSION_DB_NAME",
	"SESSION_DB_USER",
	"SESSION_DB_PASS",
	"ENABLE_IP_V6",
	);

my @nodesimple=(
	"NODENAME",
	"BUFFER_PATH",
	"SAVEDIR",
	"INTERFACE",
	"ENABLE_SESSION",
	"GUIUSER",
	"GUIPASS",
	"DONE");

my @nodeadvanced=(
	"NODENAME",
	"OFPCUSER",
	"INTERFACE",
	"BUFFER_PATH",
	"SAVEDIR",
	"OFPC_PORT",
	"VERBOSE",
	"DONE",
	"DAEMONLOGGER",
	"FILE_SIZE",
	"OFPC_Q_PID",
	"ENABLE_SESSION",
	"GUIUSER",
	"GUIPASS",
	);

my @proxy=(
	"OFPC_PORT",
	"NODEROUTE",
	);

# This is a hash of things we need to configure. It contains the variable, and the question to present to the user

$question{'ENABLE_SESSION'} = "\"ENABLE_SESSION\"\n Enable session capture/search on this node? Note: This requires cxtracker and mysql (1=on|0=off).\n";
$question{'NODENAME'} = "\"NODENAME\"\n Enter a name for this OFPC node e.g. \"London\"";
$question{'OFPCUSER'} = "\"OFPCUSER\"\n What system User ID would you like to run the openfpc process as?";
$question{'INTERFACE'} = "\"INTERFACE\"\n What interface do you want daemonlogger to run on?";
$question{'VERBOSE'} = "\"VERBOSE\"\n Run in verbose mode (WARNING this disables daemon mode (not done yet!)) \n (1=on 0=off)";
$question{'SAVEDIR'} = "\"SAVEDIR\"\n Location to save extracted sessions to";
$question{'BUFFER_PATH'} = "\"BUFFER_PATH\"\n Path to store traffic buffer, this is where you want to throw a large quantity of storage.\n";
$question{'OFPC_PORT'} = "\"OFPC_PORT\"\n TCP port for openfpc to listen on";
$question{'SESSION_DIR'} =  "\"SESSION_DIR\"\n Path to store session data (Text flow records)"; 
$question{'SESSION_DB_NAME'} = "\"SESSION_DB_NAME\"\n Name of the session database (MYSQL)";
$question{'SESSION_DB_USER'} = "\"SESSION_DB_USER\"\n Enter the username for the Database user";
$question{'SESSION_DB_PASS'} = "\"SESSION_DB_PASS\"\n Enter the password for the Database user";
$question{'DONE'} = "\"DONE\"\n Are you happy that configuration is complete and OpenFPC is allowed to start up? y/n";
$question{'DAEMONLOGGER'} = "\"DAEMONLOGGER\"\n Path to daemonlogger";
$question{'FILE_SIZE'} = "\"FILE_SIZE\" \n Size of each buffer file. E.g. \"2G\" = 2 GB, \"10M\" = 10 MB";
$question{'ENABLE_IP_V6'} = "\"ENABLE_IP_V6\" \n Enable IPv6 Support? \n (1=on, 0=off)";
$question{'OFPC_Q_PID'} = "\"OFPC_Q_PID\" \n PID file location for queue daemon";
$question{'NODEROUTE'} = "\"NODEROUTE\"\n File for OpenFPC Node routing information";
$question{'GUIUSER'} = "\"GUIUSER\"\n OpenFPCQ user ID to use when extracting pcaps via OpenFPC GUI \n(Note: this username/password needs to be in the OpenFPC user definition below)";
$question{'GUIPASS'} = "\"GUIPASS\"\n OpenFPCQ password for this user\n(Note: this username/password needs to be in the OpenFPC user definition below)";

# Input validations to make sure we get valid data as part of the setup questions.
# Format is a key, and then a pcre to m/$stuff/.
$validation{'VERBOSE'} = "(1|0)";
$validation{'ENABLE_IP_V6'} = "(1|0)";
$validation{'PORT'} = "\\d{1,5}";
$validation{'DONE'} = "(y|n)";

sub askq{
	# Ask a question, return an answer
	# I expect the variable I am to populate, and an optional default value.
	# e.g. askq("user","root");
	# I return the value the user has input, e.g root

	my $key=shift;
	my $default=shift;

	while(1) { 	# Continue forever until we receive valid input
		print "$question{$key} (Current setting:$default): ";
		my $response=<STDIN>;
		chomp $response;
		if ($response) {
			$response=lc($response);		# Keep all config in lower case
		} else {   					# No input, take default value
			$response=$default;
		}

		if (defined $validation{$key}) {
			print "Input validation check found for $key" if ($debug);
			if ($response =~ m/$validation{$key}/ ) {
				print "-> IV Passed\n" if ($debug);
				return($response);	
			} else {
				print "-> IV failed\n" if ($debug);
				print "Invalid input \"$response\". Hit CRTL+C to break out \n";
			}
		} else {
			print "No validation performed on $key\n" if ($debug);
			return($response);
		}
	}
}

sub interview{
	# Interview the user for the answers to the question array passed
	my $qnum=0;
	my @questions=@_;
	my $qcount=@questions;
	foreach my $key (@questions) {
		$qnum++;
		# If there is a value already set in the config file, provide it as
		# a default value (press enter to keep it).
		print "\n** Question $qnum/$qcount ***********************\n";
		if (defined $config{$key}) {
			$config{$key}=askq($key,$config{$key});
		} else {
			$config{$key}=askq($key,"");
		}
		print "Setting $key to $config{$key}\n" if ($debug);
	}
}

sub usage{
print<<EOF

[*] openfpc-setup.pl
    Interactive setup tool for OpenFPC
    - Leon Ward

    Usage:

    openfpc-setup.pl <args>
    -c or --config		Specify a configuration filename
    -p or --proxy		Configure a proxy device
    -d or --debug		Enable debug
    -h or --help		This message
    -a or --advanced		Advanced setup options

[-] Notes: 
 - If you specify an existing config file with -c, it will be read will be used as the default values.
 - Backups are created before overwriting any config
	
EOF
}

# ---------- Start here -----------

GetOptions (    'c|config=s' => \$cmdargs{'file'},
		'a|advanced' => \$cmdargs{'advanced'},
		'p|proxy' => \$cmdargs{'proxy'},
		'h|help' => \$cmdargs{'help'},	
		'd|debug' => \$debug,);

if ( $cmdargs{'help'}) { 	# Show usage and quit
	usage();
	exit 0;
}


if (defined $cmdargs{'file'}) {
	$file=$cmdargs{'file'};
} else {
	# Look for a file in the obvious locations
	foreach(@configfiles) {
		if ( -f $_)  {
			$file=$_;
			last;
		}
	} 
}

print "
***************************************
[*] OpenFPC Setup - Leon Ward 2010  
    An interview based setup tool for OpenFPC.
";


print "[-] Reading existing config file $file\n" ;
if (-f $file) {
	open(CONFIG,'<', "$file") or die("ERROR: Can't open config file $file\n");
	while(<CONFIG>) {
        	chomp;
	        if ( $_ =~ m/^[a-zA-Z]/) {
	                (my $key, my @value) = split /=/, $_; 
        	        unless ($key eq "USER") {
                	        $config{$key} = join '=', @value;
                	} else {
                        	$userlist{$value[0]} = $value[1] ;
                	}   
        	}   
	}
	close CONFIG;
}

if (defined $cmdargs{'advanced'}) { 				# Advanced requested
	if (defined $cmdargs{'proxy'} ) { 			# Advanced proxy
		$config{'PROXY'} = 1;
		@qlist=@proxy;
	} else {
		@qlist=@nodeadvanced;
		print "[-] Showing advanced node setup options\n";
	}
} else {
	if (defined $cmdargs{'proxy'} ) { 			# Advanced proxy
		$config{'PROXY'} = 1;
		@qlist=@proxy;
	} else {
		@qlist=@nodesimple;
		print "[-] Showing simple OpenFPC Node setup options\n";
	}
}


# Perform interview with the question set(array).
interview(@qlist);

# Add users for openfpc-queued
# Here
print "\n------ OpenFPC User definitions ------\n";
print "* Current Users:\n";
foreach my $user (keys %userlist){
	print "* Found existing user - $user\n";
	print "  Keep user? (y/n) : ";
	my $tmpin=<STDIN>;
	unless ($tmpin =~ m/(n|N|no)/i) {
		print "  Change password for $user? (y/n) : ";
		$tmpin=<STDIN>;
		if ($tmpin =~ m/(y|yes)/i) {
			print "Enter new password for user $user : ";
			$userlist{$user}=<STDIN>;
			print "Pass set to $userlist{$user}\n";
		}
	}
}

my $moreusers=0;
print "\n------ Add new users ------\n";
print "*  Add a new OpenFPC user? (y/n)";
my $tmpin=<STDIN>;
if ($tmpin =~ m/(y|yes)/i ) {
	$moreusers=1;
}

while ($moreusers) {
	print "Enter name for new user :";
	my $user = <STDIN>;
	chomp $user;
	print "\nEnter password for user $user :";
	my $pass = <STDIN>;
	chomp $pass;
	print "User $user has pass $pass\n";
	print "Add another user? (y/n) :";
	$tmpin=<STDIN>;
	$userlist{$user} = $pass;
	unless ($tmpin =~ m/(y|yes)/i ) {
		$moreusers=0;
	}
}



open(NEWCONFIG,'>', "$config{'saveconfig'}") or die("ERROR: Can't open file $config{'saveconfig'}");

print NEWCONFIG "# OpenFPC configuration file.
# Part of the OpenFPC project http://openfpc.org
# This file is autogenerated, please do not edit by hand.
# (but as I know you won't listen to that request, I will try to preserve edits you make to this file).
# - Leon
";

foreach (keys %config) {
	print NEWCONFIG "$_=$config{$_}\n";
}
foreach (keys %userlist) {
	print NEWCONFIG "USER=$_=$userlist{$_}\n";
}

# Perform follow-up actions based on user input

if ($config{'ENABLE_SESSION'})  {
	print "*******************************\n";
	print "* Session capture setup\n";
	interview(@sessionq);
	
	unless ( -d $config{'SESSION_DIR'} )  {
		print "- Creating $config{'SESSION_DIR'}\n";
		mkdir($config{'SESSION_DIR'})  or die("Unable to mkdir $config{'SESSION_DIR'}");
	}
}

# Backup existing config, and replace it with our new file.
close($config{'saveconfig'});
my $epoch=time();
if ( -f $file) {
	move($file,"$file.backup.$epoch") or die ("ERROR: Unable to backup $file to $file.backup.$epoch - Check file permissions\n");
}
move($config{'saveconfig'},$file) or die ("ERROR: Unable to save config to file $file. Check file permissions\n");

print "\n\n* Backed up old config as $file.backup.$epoch\n";
print "* Wrote config file $file\n";
######## Config file complete #########

# Enable/change password for GUI
print "\n************* IMPORTANT README *******************\n";
print "\n-----OpenFPC GUI password (Apache Basic Auth) -----\n\n" .
      "OpenFPC Doesn't yet have it's own built in GUI access control system. \n".
      "To keep things safe for now we use Apache's built in auth capability\n"; 

my ($guiuser,$guipass);
unless ( -f "$config{'INSTALL_DIR'}/apache2.passwd" ) {
	print "* No apache passwd file found. Creating one...\n";
	print "  Username: ";
	$guiuser=<STDIN>;
	chomp $guiuser;
	print "  Password: ";
	$guipass=<STDIN>;
	chomp $guipass;

	unless ( system("htpasswd -cb $config{'INSTALL_DIR'}/apache2.passwd $guiuser $guipass")) {
		print "* Password updated\n";
	} else {
		print "* Unable to create passwd file. You will have to create it by hand\n";
	}
} else {
	print "* Found existing Apache passwd file, not creating one.\n" .
	      "  Hint: You can use the below command to edit it by hand\n\n" .
	      "  \$ htpasswd $config{'INSTALL_DIR'}/apache2.passwd\n";
}

# Creating required dirs


# Complete
if ($config{'ENABLE_SESSION'})  {
	print "\n-----OpenFPC Session DB Creation/Setup -----\n\n" ;
	print "Use openfpc-dbmaint.sh to create and maintain your mysql session DB\n";
	print "This is only required on systems where session capture is enabled\n\n";
	print "  \$ /opt/openfpc/openfpc-dbmaint.sh create\n";
}

print "
**************************************************
* Setup complete!

You can now start OpenFPC with the command

 \$ sudo service openfpc start

\n";
