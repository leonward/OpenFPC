package OFPC::Config;

#########################################################################################
# Copyright (C) 2009 Leon Ward 
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
use threads::shared;
our @ISA = qw(Exporter);
@EXPORT = qw(%config
    %userlist
    %route
    %pcaps
    $verbose
    $debug
    $vdebug
    $openfpcver
    $mrid
    $queue);		
@EXPORT_OK = qw(ALL);
$VERSION = '0.5';

our $debug=0;
our $vdebug=0;
our $openfpcver=0.5;
our $rid=0;		#ÊMaster request ID. Unique for each instance.
our %config=(
    CONFIGURED  => 0,
    NODENAME    => "NONAME",
    PROXT       => 0,
    SAVEDIR     => 0,
    LOGFILE     => "/tmp/openfpc-untitled.log",
    TCPDUMP     => "/usr/sbin/tcpdump",
    MERGECAP    => "/usr/bin/mergecap",
    PIDPATH     => "/tmp",
    KEEPFILES   => "0",
    TASK_INTERVAL => 600,
    );

our %userlist=();  			# Global cache of users
our %route=();				# Hash to contain OFPC routing data for nodes
our $mrid : shared =1; $mrid=1;		# Master request counter. Quick way to identify  request
our $queue = Thread::Queue->new();	# Queue shared over all threads
our %pcaps: shared =();


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
            unless ($key eq "USER") {
		if ($value[0]){
		    $config{$key} = join '=', @value;
		}
            } else {
                print "CONF: Adding user \"$value[0]\" Pass \"$value[1]\"\n" if ($debug);
                $userlist{$value[0]} = $value[1] ;
            }
        }
    }
    close $config;
    
    my $numofusers=keys(%userlist);
    unless ($numofusers) {
        print("ERROR: $numofusers users defined in config file. You need to add some.\n");
        print("Shutting down....\n");
        exit 1
    }
    
    return(%config);    
}


1;
