#!/usr/bin/perl -I .
#########################################################################################
# Copyright (C) 2010 Leon Ward 
# ofpc-setup.pl - Part of the OpenFPC - (Full Packet Capture) project
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
my $file="./myopenfpc.conf";
my @configfiles=("/etc/ofpc.conf", "./etc/ofpc.conf");
my (%userlist, %oldconfig, %question,%validation,%cmdargs,@qlist);

# Some system defaults. If there isn't a config files to read for current values, lets give the user a 
# hint to take something sensible.

my %config=( 
                OFPCUSER => "root",  
                saveconfig => "./myofpc.conf",
		SAVEDIR => "/tmp",
		VERBOSE => "1",
		PORT => "4242",
		MASTER => 0,
		BUFFER_PATH => "/var/tmp/openfpc",
		FILE_SIZE => "10M",
		DISK_SPACE => "50",
		SESSION_DB_NAME => "openfpc",
		SESSION_DB_PASS => "openfpc",
		SESSION_DIR => "/var/tmp/ofpc_session",	
		DONE => "n",
		INTERFACE => "eth1",
		DAEMONLOGGER => "daemonlogger",
                );  

# Rather than dupe questions for different operation modes and setup styles, these are a list of questions to ask for slave/simple, slave/advanced, and in the future master/simple, master/advanced.

my @slavesimple=(
	"BUFFER_PATH",
	"SAVEDIR",
	"SESSION_DIR",
	"SESSION_DB_NAME",
	"INTERFACE",
	"SESSION_DB_PASS",
	"DONE");

my @slaveadvanced=(
	"OFPCUSER",
	"INTERFACE",
	"BUFFER_PATH",
	"SAVEDIR",
	"SESSIONDIR",
	"SESSION_DB_NAME",
	"SESSION_DB_PASS",
	"SESSOIN_DB_PORT",
	"OFPC_PORT",
	"VERBOSE",
	"DONE",
	"DAEMONLOGGER"
	"SIZE");

# This is a hash of things we need to configure. It contains the variable, and the question to present to the user
$question{'OFPCUSER'} = "What system User ID would you like to run the ofpc process as?";
$question{'INTERFACE'} = "What interface do you want daemonlogger to run on?";
$question{'VERBOSE'} = "Run in verbose mode (WARNING this disables daemon mode (not done yet!)) \n (1=on 0=off)";
$question{'SAVEDIR'} = "Location to save extracted sessions to";
$question{'BUFFER_PATH'} = "Path to store traffic buffer, this is where you want to throw a large quantity of storage.\n";
$question{'PORT'} = "TCP port for openfpc to listen on";
$question{'SESSION_DIR'} =  "Path to store session data (Text flow records)"; 
$question{'SESSION_DB_NAME'} = "Name of the session database (MYSQL)";
$question{'SESSION_DB_PASS'} = "Enter the password for the Database user";
$question{'DONE'} = "Are you happy that configuration is complete y/n";
$question{'DAEMONLOGGER'} = "Path to daemonlogger";
$question{'FILESIZE'} = "Size of each buffer file. E.g. \"2G\" = 2 GB, \"10M\" = 10 MB"l
# Input validations to make sure we get valid data as part of the setup questions.
# Format is a key, and then a pcre to m/$stuff/.
$validation{'VERBOSE'} = "(1|0)";
$validation{'PORT'} = "\d{1,5}";
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

# ---------- Start here -----------

GetOptions (    'c|config=s' => \$cmdargs{'file'},
		'a|advanced' => \$cmdargs{'advanced'},
		'm|master' => \$cmdargs{'master'},		# NOT DONE YET
		'd|debug' => \$debug,);

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

if (-f $file) {
	open(CONFIG,'<', "$file") or die("cant open config file $file");
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

print "* Reading existing config file $file\n" if ($debug);
if (defined $cmdargs{'advanced'}) { 				# Advanced requested
	if (defined $cmdargs{'master'} ) { 			# Advanced master
		die("MASTER NOT DONE YET");
	} else {
		@qlist=@slaveadvanced;
		print "* Showing advanced slave setup options\n";
	}
} else {
	if (defined $cmdargs{'master'} ) { 			# Advanced master
		die("MASTER NOT DONE YET");
	} else {
		@qlist=@slavesimple;
		print "* Showing simple slave setup options\n";
	}
}

#print Dumper %config if ($debug);
my $qcount=@qlist;
my $qnum=0;
foreach my $key (@qlist) {
	$qnum++;
	# If there is a value already set in the config file, provide it as
	# a default value (press enter to keep it).
	print "\n------ Question $qnum/$qcount -----------------------\n";
	if (defined $config{$key}) {
		$config{$key}=askq($key,$config{$key});
	} else {
		$config{$key}=askq($key,"");
	}
	print "Setting $key to $config{$key}\n" if ($debug);
}

open(NEWCONFIG,'>', "$config{'saveconfig'}") or die("cant open file $config{'saveconfig'}");

print NEWCONFIG " # OpenFPC configuration. 
# Part of the OpenFPC project http://openfpc.org
# This file is autogenerated, please do not edit by hand.
# (but as I know you won't listen to that request, I will try to preserve edits make to this file).
# - Leon
";

foreach (keys %config) {
	print NEWCONFIG "$_=$config{$_}\n";
}
close($config{'saveconfig'});

# Backup existing config, and replace it with our new file.
my $epoch=time();
if ( -f $file) {
	move($file,"$file.backup.$epoch") or die ("Unable to backup $file to $file.backup.$epoch");
}
move($config{'saveconfig'},$file) or die ("Unable to save config to file $file");

print "\n\n* Backed up old config as $file.backup.$epoch\n";
print "* Wrote config file $file\n";

