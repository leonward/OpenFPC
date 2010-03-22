#!/usr/bin/perl

#########################################################################################
# Copyright (C) 2009 Leon Ward 
# extract-pcap.pl - Part of the OpenFPC - (Full Packet Capture) project
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
use Getopt::Long qw(:config no_ignore_case bundling);
use Data::Dumper;

# So the process is.... 
#  - Take some event details from the user via command line args 
#  - Find the pcaps in the buffer location before and after the timestamp (number each way is set by --each-way)
#  - Find the packets in the pcap
#  - Extract the data requested
#  - Merge all pcaps into a single file
#  - Provide the extracted data for simple download by a user

# List of config files to look for, first one wins 
my @CONFIG_FILES=("/etc/openfpc/openfpc.conf","/opt/openfpc/openfpc.conf");
my $CONFIG_FILE;
my %CONFIG;
my $openfpcver="1.10";
my $TARGET=0;		
my %TIME_HASH=();
my @TIMESTAMPS=();
my @TARGET_PCAPS=();
my $SRC_ADDR=0;
my $DST_ADDR=0;
my $SRC_PORT=0;
my $DST_PORT=0;
my $TIMEFORMAT="sf";			# Format of timestamp (default is sf)
my $BPF=0;
my $NOW=time();
my $SUFFIX="$NOW.pcap";
my $OUTPUTFILE="extracted.$SUFFIX";
my $VERBOSE=0;
my @PCAPS=();
my $current=0;

sub convert_time()
{
	my $ts=shift;
	my $epoch=`date --date='$ts' +%s`;
	return($epoch);
}

sub decodeevent()
{
        # Attempt to decode a SF event into searchable data
        my $event=shift;
        if ($event =~ m/(.*)( high| medium| low)/) {   # Timestamp comes before priority
		$TARGET=&convert_time("$1");
        }
        if ($event =~ m/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(.*)(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {  
		$DST_ADDR=$3;
		$SRC_ADDR=$1;
        }
        if ($event =~ m/(\d{1,5})(\/tcp|\/udp| .*{2-10}\/tcp| .*{2-10}\/udp).(\d{1,5})( |\/)/) { 
		$SRC_PORT=$1;
		$DST_PORT=$3;
        }
}

sub showerror()
{
	my $message=shift;
	print "\nError: $message\n\n";
}

sub usage()
{
	print " extract-pcap.pl 
  --epoch    or -o <TIMESTAMP> 	Timestamp in epoch 
  --sf       or -f <TIMESTAMP>	Timestamp in SF format
  --src-addr or -s <SRC_ADDR> 	Source IP 
  --dst-addr or -d <DST_ADDR> 	Destination IP
  --src-port or -c <SRC_PORT>	Source Port 
  --dst-port or -p <DST_PORT>	Destination Port
  --each-way or -e <FILE COUNT> Number of pcaps each-way Default: $CONFIG{'EACHWAY'} 
  --event    or -a <EVENT_DATA> Attempt to parse a SF event table 
  --filename or -w <FILENAME>	Output pcap filename
  --verbose  or -v              Verbose output
  --all				Check in all files not just current
  --help                        This message


Example: --epoch 1234567890 --src-addr 1.1.1.1 -e 2 --dst-port 31337 
	 --sf \"2009-02-17 08:30:22\" --src-addr 1.2.3.4 \n\n";

	exit 1;
}
print "\n\n* extract-pcap.pl - \n* Part of the OpenFPC (Full Packet Capture) Project \nver $openfpcver - Leon Ward - leon\@rm-rf.co.uk\n\n";

foreach (@CONFIG_FILES) {
	if ( -f $_ ) {
		print "* Reading config file $_\n";
		$CONFIG_FILE=$_;
		last;
	}
}

# Defaults in case we don't have a config file
$CONFIG{'BUFFER_PATH'}="/var/spool/openfpc/";
$CONFIG{'SAVE_PATH'}=".";
$CONFIG{'TCPDUMP'}="tcpdump";
$CONFIG{'MERGECAP'}="mergecap";	
$CONFIG{'EACHWAY'}="1";			
$CONFIG{'CURRENT_FILE'}="/opt/openfpc/current";

# Read a config file
open my $config, '<', $CONFIG_FILE or die "Unable to open config file $CONFIG_FILE $!";
while(<$config>) {
	chomp;
        if ( $_ =~ m/^[a-zA-Z]/) {
        	(my $key, my @value) = split /=/, $_;
                $CONFIG{$key} = join '=', @value;
        }
}
close $config;

if ($VERBOSE) {
        print " ";
}

open (CURRENT_FILE,$CONFIG{'CURRENT_FILE'}) or die ("Unable to open current file \"$CONFIG{'CURRENT_FILE'}\". Have you got a buffer running?");
while (my $line = <CURRENT_FILE>){
	$current=$line;
	chomp($current);
}

if ("$#ARGV" le "0") {
	&usage;
	exit 1;
}
my $argcount=1;


# Process command line args
foreach (@ARGV) {
	if (("$_" eq "-s") || ("$_" eq "--src-addr")) {
		$SRC_ADDR=$ARGV[$argcount];
	} elsif (( "$_" eq "-d" ) || ("$_" eq "--dst-addr")) {
		$DST_ADDR=$ARGV[$argcount];
	} elsif (( "$_" eq "-c") || ("$_" eq "--src-port")){
		$SRC_PORT=$ARGV[$argcount];
	} elsif (( "$_" eq "-v") || ("$_" eq "-verbose")){
		$VERBOSE=1;	
	} elsif (( "$_" eq "-p" ) || ( "$_" eq "--dst-port")) {
		$DST_PORT=$ARGV[$argcount];
	} elsif (( "$_" eq "-w" ) || ( "$_" eq "--filename")) {
		$OUTPUTFILE=$ARGV[$argcount];
	} elsif (( "$_" eq "-e") || ( "$_" eq "--each-way")) {
		$CONFIG{'EACHWAY'}=$ARGV[$argcount];
	} elsif ( "$_" eq "--all") {
		$current="*";	
	} elsif (( "$_" eq "-a") || ( "$_" eq "--event")) {
		&decodeevent("$ARGV[$argcount]");	
	} elsif (( "$_" eq "-f") || ( "$_" eq "--sf") || ("$_" eq "-sf")) {	# Added a -sf. I made this as a common typo
		$TIMEFORMAT="sf";
		$TARGET=&convert_time($ARGV[$argcount]);
	} elsif (( "$_" eq "-o") || ( "$_" eq "--epoch")) {
		$TIMEFORMAT="epoch";
		$TARGET=$ARGV[$argcount];
	}
	$argcount++;
}


my @pcaptemp = `ls -rt $CONFIG{'BUFFER_PATH'}/buffer.$current-*`;

foreach(@pcaptemp) {
	chomp $_;
	push(@PCAPS,$_);
}



# Check we have enough settings to get a sensible pcap file

unless ($TARGET) { 
	&showerror("MUST have a timestamp set!\nWithout this you will end up with GBs of data. \nUse --each-way to expand search scope");
}

# Check that we are asking for data from a window we have in the buffer

my $firstpacket;
if (($firstpacket)=split(/ /,`$CONFIG{'TCPDUMP'} -n -tt -r $PCAPS[0] -c 1 2>/dev/null`)) {
	if ( $VERBOSE ) { 
		my $request_time = localtime($TARGET);
		my $firstpacket_localtime=localtime($firstpacket);
		my $localtime = localtime();
		print " - First buffer found is  : $PCAPS[0]\n";
		print " - First packet in buffer : $firstpacket_localtime\n"; 
		print " - Event requested is     : $request_time\n"; 
		print " - Local time is now      : $localtime\n"; 
	}
} else {
	print "Problem accessing $PCAPS[0]\n Without a buffer I cant continue";
	exit 1;
}

if ($TARGET < $firstpacket) {
	&showerror("Date requested is before the first packet in buffer - We don't have it. \nCould the event be in another set of files? Consider --all");
	exit 1;
}

if ($VERBOSE) {
	print " - Source Addr : $SRC_ADDR\n";
	print " - Source Port : $SRC_PORT\n";
	print " - Destin Addr : $DST_ADDR\n";
	print " - Destin Port : $DST_PORT\n";
}

push(@TIMESTAMPS, $TARGET); 	# Add target timestamp to our array
$TIME_HASH{$TARGET} = "TARGET"; # Method to identify our target timestamp in the hash

foreach my $pcap (@PCAPS) {
	my $timestamp = ((stat($pcap))[9]);
	$TIME_HASH{$timestamp} = $pcap;
	push(@TIMESTAMPS,$timestamp);
}

my $count=0;
my $location=0;
foreach (sort @TIMESTAMPS){		# Sort our array of timetsamps (including
	$count++;			# our target timestamp)
	if ( "$_" == "$TARGET" ) {	# Find Target Timestamp
		$location=$count;
	}
}

if ($VERBOSE) { 
	my $expectedts = ((stat($TIME_HASH{$TIMESTAMPS[$location]}))[9]);
	my $lexpectedts = localtime($expectedts);
	print " - Session is expected to be in file $TIME_HASH{$TIMESTAMPS[$location]} : $lexpectedts\n"; 
}

# Find what pcap files are eachway of target timestamp
my $precount=$CONFIG{'EACHWAY'};
my $postcount=$CONFIG{'EACHWAY'};
push(@TARGET_PCAPS,$TIME_HASH{$TIMESTAMPS[$location]});

while($precount >= 1) {
	my $file=$location-$precount;
	if ($TIME_HASH{$TIMESTAMPS[$file]}) {
		unless ( "$TIME_HASH{$TIMESTAMPS[$file]}" eq "TARGET" ) {
			push(@TARGET_PCAPS,$TIME_HASH{$TIMESTAMPS[$file]});
		}
	}
	$precount--;
}

while($postcount >= 1) {
	my $file=$location+$postcount;
	if ($TIME_HASH{$TIMESTAMPS[$file]}) {
		unless ( "$TIME_HASH{$TIMESTAMPS[$file]}" eq "TARGET" ) {
			push(@TARGET_PCAPS,$TIME_HASH{$TIMESTAMPS[$file]});
		}
	}
	$postcount--;
}

if ($VERBOSE) { 
	print " - Extracting from the following pcap files ($CONFIG{'EACHWAY'} each side of $TIME_HASH{$TIMESTAMPS[$location]})\n"; 
	foreach (@TARGET_PCAPS) {
		print "   - $_ \n";
	}
}

# Calculate BPF for extraction
# -----------------------------------------------------
my $HBPF="";
my $PBPF="";

if ($SRC_ADDR) {
	$HBPF="host $SRC_ADDR";
}

if ($DST_ADDR) {
	if ($SRC_ADDR) {
		$HBPF=$HBPF . " and ";
	}
	$HBPF=$HBPF . "host $DST_ADDR";
}

if ($SRC_PORT) {
	$PBPF="port $SRC_PORT";
	}

if ($DST_PORT) {
	if ($SRC_PORT) {
		$PBPF=$PBPF . " and ";
	}
	$PBPF=$PBPF . "port $DST_PORT";
	}

if ($HBPF and $PBPF) {
	$PBPF=" and " . $PBPF;
}
$BPF="$HBPF $PBPF";

if (("$BPF" eq  "0") || ("$BPF" eq " " )) {
	&showerror("No BPF Specified. Limit search scope with --src-addr, --dst-addr, --src-port or --dest-port");
}

if ($VERBOSE) { print " - BPF used for extraction is $BPF\n"}
# -----------------------------------------------------

print " - Searching";
if ($VERBOSE) {
	print "\n"
}

my $pcapcount=1; 
my @outputpcaps=();

foreach (@TARGET_PCAPS){
	(my $pcappath, my $pcapid)=split(/-/, $_);
	print ".";
	chomp $_;
	my $filename="$CONFIG{'SAVE_PATH'}/output-$pcapid.pcap";
	push(@outputpcaps,$filename);
	`$CONFIG{'TCPDUMP'} -r $_ -w $filename $BPF > /dev/null 2>&1`;

	if ($VERBOSE) {
		my $size = -s $filename;
		print " - File $filename is $size bytes\n";
	}
}
print "\n";

# Now that we have some pcaps, lets concatinate them into a single file
print " - Merging..\n";

if ( -d "$CONFIG{'SAVE_PATH'}" ) {
	if ($VERBOSE) {
		print " - Found save path $CONFIG{'SAVE_PATH'}\n";
	}
} else {
	die "Save path $CONFIG{'SAVE_PATH'} not found!"
}

if ($VERBOSE) {
	print " - Merge command is \"$CONFIG{'MERGECAP'} -w $CONFIG{'SAVE_PATH'}/$OUTPUTFILE @outputpcaps\" \n";
}

if (system("$CONFIG{'MERGECAP'} -w $CONFIG{'SAVE_PATH'}/$OUTPUTFILE @outputpcaps")) {
	print "Problem merging pcap file!\n Is the mergecap command in $CONFIG{'MERGECAP'} ? Check your buffer.conf!\n";
	exit 1;
}

my $filesize=`ls -lh $CONFIG{'SAVE_PATH'}/$OUTPUTFILE |awk '{print \$5}'`;		# Breaking out to a shell rather than stat for a human readable filesize
chomp $filesize;
print " - Created $CONFIG{'SAVE_PATH'}/$OUTPUTFILE ($filesize)\n";

# Clean up...
foreach(@outputpcaps)
{
	unlink($_);
}
