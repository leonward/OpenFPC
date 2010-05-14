#!/usr/bin/perl -I /opt/openfpc/ .

#########################################################################################
# Copyright (C) 2009 Leon Ward 
# ofpc-extract.pl - Part of the OpenFPC - (Full Packet Capture) project
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
use Data::Dumper;
use Getopt::Long;
use ofpcParse;

# List of config files to look for, first one wins 
my @CONFIG_FILES=("/etc/openfpc/openfpc.conf","/opt/openfpc/openfpc.conf","openfpc.conf");
my $CONFIG_FILE;
my %config;
my $openfpcver="0.1";
my $eachway=1;
my $now=time();
my $verbose=0;
my @filelist=();
my $firstpacket=0;
my $sizeofarray=0;
my @PCAPS=();

my %cmdargs=(
	'sip' => 0,
	'dip' => 0,
	'spt' => 0,
	'dpt' => 0,
	'startTime' => 0,
	'endTime' => 0,
	'outputFile' => "extracted-$now.pcap"
);

my $timestamp=0;
my $mode=0;
my $currentRun=0;		# suffix of buffer filename for current running process
my $sf=0;

my ($debug,$quiet,$http,$event,$help);

GetOptions ( 	't|time=s' => \$timestamp,
		's|src-addr=s' => \$cmdargs{'sip'},
		'd|dst-addr=s' => \$cmdargs{'dip'}, 
		'u|src-port=s' => \$cmdargs{'spt'},
		'r|dst-port=s' => \$cmdargs{'dpt'},
		'w|write=s' => \$cmdargs{'outputFile'},
		'h|help' => \$help,
		'l|http' => \$http,
		'b|start|starttime=s' => \$cmdargs{'startTime'},
		'j|end|endtime=s' => \$cmdargs{'endTime'},
		'e|eachway=i' => \$eachway,
		'a|event=s' => \$event,
		'debug' => \$debug,
		'm|mode=s' => \$mode,
		'q|quiet' => \$quiet,
		'v|verbose' => \$verbose,
		'sf' => \$sf,
		);

sub usage()
{
        print "- Usage:

  --mode     or -m <at|window> 		At a specific time, or search in a window	  
  --src-addr or -s <SRC_ADDR>           Source IP 
  --dst-addr or -d <DST_ADDR>           Destination IP
  --src-port or -u <SRC_PORT>           Source Port 
  --dst-port or -r <DST_PORT>           Destination Port
  --write    or -w <FILENAME>		Output file

  --http     or -l		        Output in HTML for download
  --verbose  or -v                      Verbose output
  --debug				Debug output 
  --quiet				Return only a filename or an error
  --all                                 Check in all buffers not just current sniff buffer

  ***** Operation Mode Specific Stuff *****

  \"At\" mode.
  --each-way or -e <FILE COUNT>         Number of pcaps each-way Default: $eachway
  --event    or -a <EVENT_DATA>         Parse a supported event log line e.g. Snort, Sourcefire, Exim etc
  --timestamp or -t			Event mode - Look each way of this epoch value
  --sf                   	        Timestamp in SF format, convert it

 \"Window\" mode.
  --start    or -b                      Start timestamp for searching in absolute mode
  --end      or -j                      End timestamp for searching is absolute mode

Example: -a -t 1234567890 --src-addr 1.1.1.1 -e 2 --dst-port 31337 --src-addr 1.2.3.4 \n";

        exit 1;
}


sub mkBPF($) {
	# Give me an event hash, and ill give you a bpf
	my %eventdata=%{$_[0]};
	my @eventbpf=();
	my $bpfstring;

	if ($eventdata{'proto'}) {
		$eventdata{'proto'} = lc $eventdata{'proto'}; # In case the tool provides a protocol in upper case
	}

	if ( $eventdata{'sip'} xor $eventdata{'dip'} ) { # One sided bpf
		if ($eventdata{'sip'} ) { push(@eventbpf, "host $eventdata{'sip'}" ) }
		if ($eventdata{'dip'} ) { push(@eventbpf, "host $eventdata{'dip'}" ) }
	}

	if ( $eventdata{'sip'} and $eventdata{'dip'} ) {
		 push(@eventbpf, "host $eventdata{'sip'}" );
		 push(@eventbpf, "host $eventdata{'dip'}" );
	}
	
	if ( $eventdata{'spt'} xor $eventdata{'dpt'} ) { 
		if ($eventdata{'spt'} ) { push(@eventbpf, "$eventdata{'proto'} port $eventdata{'spt'}" ) }
		if ($eventdata{'dpt'} ) { push(@eventbpf, "$eventdata{'proto'} port $eventdata{'dpt'}" ) }
	}

	if ( $eventdata{'spt'} and $eventdata{'dpt'} ) {
		 push(@eventbpf, "$eventdata{'proto'} port $eventdata{'spt'}" );
		 push(@eventbpf, "$eventdata{'proto'} port $eventdata{'dpt'}" );
	}

	# cat the eventbpf array into a string
	foreach (@eventbpf) {
		if ($bpfstring) { 
			$bpfstring = $bpfstring . " and "; 
		} else {
			$bpfstring = $_ ;
			next;
		}
		$bpfstring = $bpfstring . $_ . " ";
	}

	if ($verbose) { print "- EventBPF created is $bpfstring\n"; }
	return($bpfstring);
}

sub findBuffers {
        # Pass me a timestamp and number of files,
        # and ill give you some pcap filenames you can search over

        my $targetTimeStamp=shift;
        my $numberOfFiles=shift;
        my @TARGET_PCAPS=();
        my %timeHash=();
	my @timestampArray=();

        if ($debug) {
                print " - $numberOfFiles requested each side of target timestamp \n";
        }

	$targetTimeStamp=$targetTimeStamp-0.5;			# Remove risk of TARGET conflict with file timestamp.	
        push(@timestampArray, $targetTimeStamp);            	# Add target timestamp to an array of all file timestamps
        $timeHash{$targetTimeStamp} = "TARGET";             	# Method to identify our target timestamp in the hash

        foreach my $pcap (@PCAPS) {
                my $timestamp = ((stat($pcap))[9]);
                if ($debug) {
                        print " - Adding file $pcap with timestamp $timestamp (" . localtime($timestamp) . ") to hash of timestamps \n";
                }
                $timeHash{$timestamp} = $pcap;
                push(@timestampArray,$timestamp);
        }

        my $location=0;
	my $count=0; 		
	print "-----------------Array----------------\n";
	if ($debug) {		# Yes I do this twice, but it helps me debug timestamp pain!
		foreach (sort @timestampArray) {
			print " $count";
			print " - $_ $timeHash{$_}\n";
			$count++;
		}
	}
	print "-------------------------------------\n";

	$location=0;
        $count=0;
        foreach (sort @timestampArray){                 # Sort our array of timetsamps (including
                $count++;                               # our target timestamp)
		if ($debug) {
			print " + $count - $_ $timeHash{$_}\n";
		}

		if ( "$timeHash{$_}" eq "TARGET" ) {
			$sizeofarray=@timestampArray - 1;
			$location=$count - 1;
			if ($debug) {
				print " - Got TARGET match of $_ in array location $count\n";
				print "   Pcap file at previous to TARGET is in location $location -> filename $timeHash{$timestampArray[$location]} \n";
			}
			last;
		} elsif ( "$_" == "$targetTimeStamp" ) {     # If the timestamp of the pcap file is identical to the timestamp
                        $location=$count;               # we are looking for (corner case), store its place
                        $sizeofarray=@timestampArray - 1 ;
                        if ($debug) {
                                print " - Got TIMESTAMP match of $_ in array location $count\n";
				print "   Pcap file associated with $_ is $timeHash{$timestampArray[$location]}\n";
                        }
			last;
		}
        }

        if ($debug) {
                if (my $expectedts = ((stat($timeHash{$timestampArray[$location]}))[9])) { 
                	my $lexpectedts = localtime($expectedts);
                	if ($verbose) {
                        	print " - Target PCAP filename is $timeHash{$timestampArray[$location]} : $lexpectedts\n";
                	}
		}
        }

        # Find what pcap files are eachway of target timestamp
        my $precount=$numberOfFiles;
        my $postcount=$numberOfFiles;
	unless ( $timeHash{$timestampArray[$location]} eq "TARGET" ) {
        	push(@TARGET_PCAPS,$timeHash{$timestampArray[$location]});
	} else {
		print "Skipping got target\n";
	}

        while($precount >= 1) {
                my $file=$location-$precount;
                if ($file < 0 ){        # I the range to search is out of bounds
                        if ($debug) {
                                print " - Eachway generated an OOB earch at location $file in array. Thats le 0!\n";
                        }
                } else {
                        if ($timeHash{$timestampArray[$file]}) {
                                unless ( "$timeHash{$timestampArray[$file]}" eq "TARGET" ) {
                                        push(@TARGET_PCAPS,$timeHash{$timestampArray[$file]});
                                }
                        }
                }
                $precount--;
        }

        while($postcount >= 1) {
                my $file=$location+$postcount;
                if ($file > (@timestampArray - 1) ) {       # I the range to search is out of bounds
                        if ($debug) {
                                print " - Eachway generated an OOB search at location $file in array. Skipping each way value too high \n";
                        }
                } else {
                        if ($timeHash{$timestampArray[$file]}) {
                                unless ( "$timeHash{$timestampArray[$file]}" eq "TARGET" ) {
                                        push(@TARGET_PCAPS,$timeHash{$timestampArray[$file]});
                                }
                        }
                }
                $postcount--;
        }
	if ($debug) {
		print "* Search scope : ";
		foreach (@TARGET_PCAPS) {
			print "$_ \n";
		}
		print "\n";
	}
        return(@TARGET_PCAPS);
}

sub doSearch{
	my %eventdata=();
	my @startFile=findBuffers("$cmdargs{'startTime'}","0");
	my @endFile=findBuffers("$cmdargs{'endTime'}","0");

	if ($verbose) {
		print " * Starting search in file 	: $startFile[0] \n";
		print " * Ending search in file 	: $endFile[0] \n";
	}
	
	(my $startFilename, my $startFileSuffix)=split(/-/, $startFile[0]);
	(my $endFilename, my $endFileSuffix)=split(/-/, $endFile[0]);

	if ($debug) {
		print " - StartFile/Endfile are $startFileSuffix / $endFileSuffix\n";
	}
	push(@filelist,"$startFilename-$startFileSuffix");	
	while ($startFileSuffix != $endFileSuffix) {
		$startFileSuffix++;
		if ($startFileSuffix <10) {
			$startFileSuffix = "0".$startFileSuffix;
		}	
		push(@filelist,"$startFilename-$startFileSuffix");
		if ($startFileSuffix >= $sizeofarray) {
			if ($debug) { print " - Wrapping suffix search back to 00"; }
			$startFileSuffix="00";
		}
	}
	if ($verbose) {
		print "*  Exteact file list \n";
	        foreach my $foo (@filelist){
        	        print " - $foo \n";
        	}
	}

	# Check we have enough args to do some type of sensible search
	unless ($cmdargs{'sip'} or $cmdargs{'dip'} or $cmdargs{'spt'} or $cmdargs{'dpt'} ) {
		die("Not enough constraints added. Won't extact");
	}

	$eventdata{'sip'} = $cmdargs{'sip'};
	$eventdata{'dip'} = $cmdargs{'dip'};
	$eventdata{'spt'} = $cmdargs{'spt'};
	$eventdata{'dpt'} = $cmdargs{'dpt'};


	my $bpf=mkBPF(\%eventdata);
	&doExtract($bpf);
}


sub doExtract{
	my $bpf=shift;
	my $pcapcount=1;
	my @outputpcaps=();
	if ($verbose) {
		print "* Doing Extraction with BPF $bpf\n";
	}
	unless ($http or $quiet) { print " - Searching for traffic"; }
	foreach (@filelist){
        	(my $pcappath, my $pcapid)=split(/-/, $_);
        	unless ($http or $verbose or $quiet) { print "."; }
        	chomp $_;
        	my $filename="$config{'SAVE_PATH'}/output-$pcapid.pcap";
        	push(@outputpcaps,$filename);
		my $exec="$config{'TCPDUMP'} -r $_ -w $filename $bpf > /dev/null 2>&1";	
		if ($verbose) { 
			print " - Running $exec \n";
		}

		`$exec`;
	}
	unless ($quiet) { print "\n"; }

	# Now that we have some pcaps, lets concatinate them into a single file
	unless ($http or $quiet) {
        	print " - Merging ...\n";
	}

	if ( -d "$config{'SAVE_PATH'}" ) {
        	if ($verbose) {
               		print " - Found save path $config{'SAVE_PATH'}\n";
        	}
	} else {
        	die("Save path $config{'SAVE_PATH'} not found!")
	}

	if ($verbose) {
        	print " - Merge command is \"$config{'MERGECAP'} -w $config{'SAVE_PATH'}/$cmdargs{'outputFile'} @outputpcaps\" \n";
	}

	if (system("$config{'MERGECAP'} -w $config{'SAVE_PATH'}/$cmdargs{'outputFile'} @outputpcaps")) {
        	die("Problem merging pcap file!\n Run in verbose mode to debug\n");
	}

	my $filesize=`ls -lh $config{'SAVE_PATH'}/$cmdargs{'outputFile'} |awk '{print \$5}'`;                # Breaking out to a shell rather than stat for a human readable filesize
	chomp $filesize;
	if ($filesize eq 24) {
		print "EMPTY\n";
	}

	if ($http) {
        	print "<a href=\"$config{'HYPERLINK_PATH'}/$cmdargs{'outputFile'}\">Download $cmdargs{'outputFile'} ($filesize Bytes)</a>";
	} elsif ($quiet) {
		print "$config{'SAVE_PATH'}/$cmdargs{'outputFile'}\n";
	} else {
        	print " - Created $config{'SAVE_PATH'}/$cmdargs{'outputFile'} ($filesize Bytes)\n";
	}

	# Clean up temp files that have been merged...
	foreach(@outputpcaps)
	{
		if ($debug) { print "Unlinking temp file : $_ \n"; }
        	unlink($_);
	}
}

sub doAt{	
	@filelist=(findBuffers("$timestamp", "$eachway"));
	if ($debug) {
		print " ----- Extract will be performed against the following files -----\n";
	        foreach (@filelist){
        	        print " - $_\n";
        	}
		print " -----/ File Roster ------\n";
	}

	# Because we don't have a real log line, lets create a fake eventdata hash from command
	# line args

	my %eventdata=();
	$eventdata{'sip'} = $cmdargs{'sip'};
	$eventdata{'dip'} = $cmdargs{'dip'};
	$eventdata{'spt'} = $cmdargs{'spt'};
	$eventdata{'dpt'} = $cmdargs{'dpt'};

	# Check we have enough args to do some type of sensible search
	unless ($cmdargs{'sip'} or $cmdargs{'dip'} or $cmdargs{'spt'} or $cmdargs{'dpt'} ) {
		die("Not enough constraints added. Won't extact");
	}
	my $bpf=mkBPF(\%eventdata);
	doExtract($bpf);
}


sub doEvent{
	my $logline=shift;

	my %eventdata = (); 

	# Work through a list of file-parsers until we get a hit	
	while (1) {
        	%eventdata=ofpcParse::SF49IPS($logline); if ($eventdata{'parsed'} ) { last; }
        	%eventdata=ofpcParse::Exim4($logline); if ($eventdata{'parsed'} ) { last; }
        	%eventdata=ofpcParse::SnortSyslog($logline); if ($eventdata{'parsed'} ) { last; }
        	%eventdata=ofpcParse::SnortFast($logline); if ($eventdata{'parsed'} ) { last; }
        	die("Unable to parse this log line. It Doesn't match any of my parsers. Sorry!")
	}

	if ($debug) {
		print " ---Decoded Event---\n" .
			"Type: $eventdata{'type'}\n" .
			"Timestamp: $eventdata{'timestamp'} (" . localtime($eventdata{'timestamp'}) . ")\n" .
			"SIP: $eventdata{'sip'}\n" .
			"DIP: $eventdata{'dip'}\n" .
			"SPT: $eventdata{'spt'}\n" .
			"DPT: $eventdata{'dpt'}\n" .
			"Protocol: $eventdata{'proto'}\n" .
			"Message: $eventdata{'msg'}\n" ;
	}

	# Do some sanity checks on the timestamp
	if ($eventdata{'timestamp'} < $firstpacket) {
		die("Date requested is before FirstPacket ($firstpacket " . localtime($firstpacket) . ") and therefore outside the range of the packet in buffer - We don't have it. \nCould the event be in another set of files? Consider --all\n");
	
	}

	if ($eventdata{'timestamp'} > $now) {
		die("Historical date requested is in the future. Clearly you have a ntp problem.");
	}

	my $bpf=mkBPF(\%eventdata);
	@filelist=(findBuffers($eventdata{'timestamp'}, $eachway));
	doExtract($bpf);	
}

sub doInit{
	# Do the stuff that's required regardless of mode of operation

	open (CURRENT_FILE,"$config{'CURRENT_FILE'}") or die("Unable to open current file \"$config{'CURRENT_FILE'}\". Have you got a buffer running?");
	while (my $line = <CURRENT_FILE>){
        	$currentRun=$line;
        	chomp($currentRun);
		if ($debug) {
			print " - Current running buffer suffix is $currentRun\n";
		}
	}
	close (CURRENT_FILE);
	my @pcaptemp = `ls -rt $config{'BUFFER_PATH'}/buffer.$currentRun-*`;
	foreach(@pcaptemp) {
        	chomp $_;
        	push(@PCAPS,$_);
	}
	
	# Get info about the traffic buffer
	if (($firstpacket)=split(/ /,`$config{'TCPDUMP'} -n -tt -r $PCAPS[0] -c 1 2>/dev/null`)) {
        	if ( $verbose ) {
	                my $firstpacket_localtime=localtime($firstpacket);
        	        my $localtime = localtime();
			print " ---------Traffic Buffer Data-----------\n";
                	print " - First buffer found is  : $PCAPS[0]\n";
                	print " - First packet in buffer : $firstpacket_localtime\n";
                	print " - Local time is now      : $localtime\n";
        	}
	} else {
        	die("Problem accessing $PCAPS[0]\n Without a buffer I cant continue");
	}
}

################# Start processing here ####################

print STDERR "
* ofpc-extract.pl  - Part of the OpenFPC Project *
  Leon Ward - leon\@rm-rf.co.uk 
-------------------------------------------------- \n\n";

# Some "sane" defaults to work with in case there isn't a config file
$config{'BUFFER_PATH'}="/var/spool/openfpc/";
$config{'SAVE_PATH'}=".";
$config{'TCPDUMP'}="tcpdump";
$config{'MERGECAP'}="mergecap";
$config{'EACHWAY'}="1";
$config{'CURRENT_FILE'}="/opt/openfpc/current";
$config{'HYPERLINK_PATH'}="/pcaps/";

# Decide what config file to read
foreach (@CONFIG_FILES) {
        if ( -f $_ ) {
                if ($verbose) {
			print STDERR "* Reading config file $_\n";
		}
                $CONFIG_FILE=$_;
                last;
        }
}
open my $config, '<', $CONFIG_FILE or die "Unable to open config file $CONFIG_FILE $!";
while(<$config>) {
        chomp;
        if ( $_ =~ m/^[a-zA-Z]/) {
                (my $key, my @value) = split /=/, $_;
                $config{$key} = join '=', @value;
        }
}
close $config;

# Display command line options and config file settings
if ($debug) {
	print "* Dumping command line options \n" .
		"   timestamp = $timestamp " . localtime($timestamp) . "\n" .
		"   mode = $mode \n" .
		"   event = $event \n" .
		"   src_addr = $cmdargs{'sip'} \n" .
		"   dst_addr = $cmdargs{'dip'} \n" .
		"   src_port = $cmdargs{'spt'} \n" .
		"   dst_port = $cmdargs{'dpt'} \n" .
		"   eachway  = $eachway \n" .
		"   write    = $cmdargs{'outputFile'} \n" .
		"   Starttime = $cmdargs{'startTime'} (". localtime($cmdargs{'startTime'}) . ") \n" .
		"   Endtime   = $cmdargs{'endTime'} (". localtime($cmdargs{'endTime'}) . ")\n" ;
}

##### Decide what to do.

if ($help) {
	usage;
	exit 0;
}

if ( ($mode eq "window") or ($mode eq "w") or ($cmdargs{'startTime'} and $cmdargs{'endTime'})) {
	if ($verbose) {
		print "*  Running in time window mode\n";
	}
	if ( $cmdargs{'startTime'} > $cmdargs{'endTime'} ) {
		die("Start time is gt than end time. Something's wrong there");
	}

	doInit;
	doSearch;

} elsif ( ($mode eq "at") or ($mode eq "a")) {
	if ($verbose) {
		print "*  Running in \"At\" mode\n";
	}

	# Process and convert timestamp if required from different formats.
	unless ($timestamp) {
		$timestamp=$now;
		print STDERR " - Warning: Timestamp not specified, Assuming \"now\" of $now " . localtime($now) ." \n";
	}
	if ($sf) {	
		if ($verbose) {
			print " - Got timestamp in SF format \"$timestamp\"\n";
		}

        	my $epoch=`date --date='$timestamp' +%s` or die("Unable to convert SF format timestamp $timestamp to epoch. Are you sure its valid");
        	chomp $epoch;
		$timestamp=$epoch;
		if ($debug) {
			print " - Converted SF timestamp to $timestamp\n";
		}	
	}

	doInit;

	my $request_time = localtime($timestamp);
	if ($verbose) {
        	print " - Event requested is     : $request_time\n";
	}
	if (($timestamp < $firstpacket) or ($timestamp > time())) {
        	die("Date requested is before $firstpacket " . localtime($firstpacket) . " and therefore outside the range of the packet in buffer - We don't have it. \nCould the event be in another set of files? Consider --all\n");
        	exit 1;
	}

	doAt;

} elsif ($event) {	# Process a log-line and extract session(s)
	if ($verbose) {
		print "* Running in Event (log line) mode\n";	
	}
	doInit;
	doEvent($event);
} else {
	print STDERR "Error, You need to tell me what to do!\n";
	print STDERR "Take a look at --help\n";
	exit 1;
}


