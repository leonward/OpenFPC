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
    $daemon
    $queue);		
@EXPORT_OK = qw(ALL);
$VERSION = '0.6';

our $debug=0;
our $daemon=0;		# Daemon mode
our $vdebug=0;
our $openfpcver=0.6;
our $rid=0;		#ÊMaster request ID. Unique for each instance.
our %config=(
    CONFIGURED  => 0,
    NODENAME    => "NONAME",
    PROXY       => 0,
    SAVEDIR     => 0,
    LOGFILE     => "/tmp/openfpc-untitled.log",
    TCPDUMP     => "/usr/sbin/tcpdump",
    MERGECAP    => "/usr/bin/mergecap",
    PIDPATH     => "/var/run",
    KEEPFILES   => "0",
    TASK_INTERVAL => 600,
    PASSWD	=> 0,
    );

our %userlist=();  			# Global cache of users
our %route=();				# Hash to contain OFPC routing data for nodes
our $mrid : shared =1; $mrid=1;		# Master request counter. Quick way to identify  request
our $queue = Thread::Queue->new();	# Queue shared over all threads
our %pcaps: shared =();







1;
