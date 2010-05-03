#!/usr/bin/perl -I . /opt/openfpc/

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
my @CONFIG_FILES=("/etc/openfpc/openfpc.conf","/opt/openfpc/openfpc.conf");
my $CONFIG_FILE;
my %config;
my $openfpcver="1.10";
my $eachway=1;
my $now=time();
my $verbose=0;
my @filelist=();
my $firstpacket=0;
my $sizeofarray=0;
my @PCAPS=();

my $src_addr=0;
my $dst_addr=0;
my $src_port=0;
my $dst_port=0;
my $timestamp=0;
my $outputFile="ofpc-$now.pcap";
my $help=0;
my $http=0;
my $startTime=0;
my $endTime=0;
my $event=0;
my $mode=0;
my $currentRun=0;		# suffix of buffer filename for current running process
my $sf=0;

GetOptions ( 	't|time=s' => \$timestamp,
		's|src-addr=s' => \$src_addr ,
		'd|dst-addr=s' => \$dst_addr, 
		'q|src-port=s' => \$src_port,
		'r|dst-port=s' => \$dst_port,
		'w|write=s' => \$outputFile,
		'h|help' => \$help,
		'l|http' => \$http,
		'b|start|starttime=s' => \$startTime,
		'j|end|endtime=s' => \$endTime,
		'e|eachway=i' => \$eachway,
		'a|event=s' => \$event,
		'm|mode=s' => \$mode,
		'v|verbose' => \$verbose,
		'sf' => \$sf,
		);

sub showerror($) {
	my $message=shift;

	# Present an error to the user. Die works great, but when output in HTML mode
	# we also went to show the problem to the user
	print "Error : $message";
	die("$message");
}

sub usage()
{
        print "- Usage:

  --mode     or -m <at|window> 		At a specific time, or search in a window	  
  --src-addr or -s <SRC_ADDR>           Source IP 
  --dst-addr or -d <DST_ADDR>           Destination IP
  --src-port or -c <SRC_PORT>           Source Port 
  --dst-port or -p <DST_PORT>           Destination Port
  --write    or -w <FILENAME>		Output file

  --http     or -l		        Output in HTML for download
  --verbose  or -v                      Verbose output
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


sub findBuffers {
        # Pass me a timestamp and number of files,
        # and ill give you some pcap filenames you can search over

        my $targetTimeStamp=shift;
        my $numberOfFiles=shift;
        my @TARGET_PCAPS=();
        my %timeHash=();
	my @timestampArray=();

        if ($verbose) {
                print " - $numberOfFiles requested each side of target timestamp \n";
        }
	
        push(@timestampArray, $targetTimeStamp);            # Add target timestamp to an array of all file timestamps
        $timeHash{$targetTimeStamp} = "TARGET";             # Method to identify our target timestamp in the hash

        foreach my $pcap (@PCAPS) {
                my $timestamp = ((stat($pcap))[9]);
                if ($verbose) {
                        #print " - Adding file $pcap with timestamp $timestamp (" . localtime($timestamp) . ") to hash of timestamps \n";
                }
                $timeHash{$timestamp} = $pcap;
                push(@timestampArray,$timestamp);
        }

        my $count=0;
        my $location=0;
        foreach (sort @timestampArray){                 # Sort our array of timetsamps (including
                $count++;                               # our target timestamp)
                if ( "$_" == "$targetTimeStamp" ) {     # Find Target Timestamp
                        $location=$count;               # And store its place
                        $sizeofarray=@timestampArray - 1 ;
                        if ($verbose) {
                                print " - Found location of target timestamp $targetTimeStamp in hash. Position $location of " . $sizeofarray . " pcap files\n";
                        }
		last;
                }
        }
        if ($verbose) {
                my $expectedts = ((stat($timeHash{$timestampArray[$location]}))[9]);
                my $lexpectedts = localtime($expectedts);
                if ($verbose) {
                        print " - Target PCAP filename is $timeHash{$timestampArray[$location]} : $lexpectedts\n";
                }
        }


        # Find what pcap files are eachway of target timestamp
        my $precount=$numberOfFiles;
        my $postcount=$numberOfFiles;
        push(@TARGET_PCAPS,$timeHash{$timestampArray[$location]});

        while($precount >= 1) {
                my $file=$location-$precount;
                if ($file < 0 ){        # I the range to search is out of bounds
                        if ($verbose) {
                                print " - Out of bounds search at location $file in array. Thats le 0!\n";
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
                        if ($verbose) {
                                print " - Out of bounds search at location $file in array. Skipping each way value too high \n";
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
	if ($verbose) {
		print "* Search scope : ";
		foreach (@TARGET_PCAPS) {
			print "$_ \n";
		}
		print "\n";
	}
        return(@TARGET_PCAPS);
}

sub mkBPF(){
	# ----------------------
	# Calculate BPF for extraction
	# -----------------------------------------------------
	my $hbpf="";
	my $pbpf="";

	if ($src_addr) {
       		$hbpf="host $src_addr";
	}

	if ($dst_addr) {
       		if ($src_addr) {
               		$hbpf=$hbpf . " and ";
       		}
       		$hbpf=$hbpf . "host $dst_addr";
	}

	if ($src_port) {
       		$pbpf="port $src_port";
       		}

	if ($dst_port) {
       		if ($src_port) {
               		$pbpf=$pbpf . " and ";
       		}
       		$pbpf=$pbpf . "port $dst_port";
       	}

	if ($hbpf and $pbpf) {
       		$pbpf=" and " . $pbpf;
	}

	my $bpf="$hbpf $pbpf";
	if ($verbose) {
		print " - BPF Generated as $bpf\n";
	}

	if (("$bpf" eq  "0") || ("$bpf" eq " " )) {
        	showerror("Fatal Search scope too large. \n" .
				"Source address =  $src_addr\n" .
				"Destination address = $dst_addr \n" .
				"Source port = $src_port \n" .
				"Destination port = $dst_port \n".
				"Is too large. Please limit it with some constraints");
	}
	return($bpf);
}

sub doSearch{
	if ($verbose) {
		print "*  Running in Search mode\n";
	}
	my @startFile=findBuffers("$startTime","0");
	my @endFile=findBuffers("$endTime","0");

	if ($verbose) {
		print " * Starting search in file 	: $startFile[0] \n";
		print " * Ending search in file 	: $endFile[0] \n";
	}
	
	(my $startFilename, my $startFileSuffix)=split(/-/, $startFile[0]);
	(my $endFilename, my $endFileSuffix)=split(/-/, $endFile[0]);

	if ($verbose) {
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
			if ($verbose) {
				print " - Wrapping suffix search back to 00";
			}
			$startFileSuffix="00";
		}
	}
	if ($verbose) {
		print "*  Exteact file list \n";
	        foreach my $foo (@filelist){
        	        print " - $foo \n";
        	}
	}
	my $bpf=mkBPF();
	&doExtract($bpf);
}


sub doExtract{
	my $bpf=shift;
	my $pcapcount=1;
	my @outputpcaps=();
	if ($verbose) {
		print "- Doing Extraction with BPF $bpf\n";
	}
	unless ($http) {
		print " - Searching ";
	}
	foreach (@filelist){
        	(my $pcappath, my $pcapid)=split(/-/, $_);
        	unless ($http or $verbose) { print "."; }
        	chomp $_;
        	my $filename="$config{'SAVE_PATH'}/output-$pcapid.pcap";
        	push(@outputpcaps,$filename);
		my $exec="$config{'TCPDUMP'} -r $_ -w $filename $bpf > /dev/null 2>&1";	
		if ($verbose) { 
			print " - Running $exec \n";
		}

		`$exec`;
	}
	print "\n";

	# Now that we have some pcaps, lets concatinate them into a single file
	unless ($http) {
        	print " - Merging..\n";
	}

	if ( -d "$config{'SAVE_PATH'}" ) {
        	if ($verbose) {
               		print " - Found save path $config{'SAVE_PATH'}\n";
        	}
	} else {
        	shorerror("Save path $config{'SAVE_PATH'} not found!")
	}

	if ($verbose) {
        	print " - Merge command is \"$config{'MERGECAP'} -w $config{'SAVE_PATH'}/$outputFile @outputpcaps\" \n";
	}

	if (system("$config{'MERGECAP'} -w $config{'SAVE_PATH'}/$outputFile @outputpcaps")) {
        	print "Problem merging pcap file!\n Run in verbose mode to debug\n";
        	exit 1;
	}

	my $filesize=`ls -lh $config{'SAVE_PATH'}/$outputFile |awk '{print \$5}'`;                # Breaking out to a shell rather than stat for a human readable filesize
	chomp $filesize;

	if ($http) {
        	print "<a href=\"$config{'HYPERLINK_PATH'}/$outputFile\">Download $outputFile ($filesize Bytes)</a>";
	} else {
        	print " - Created $config{'SAVE_PATH'}/$outputFile ($filesize)\n";
	}
	# Clean up...
	foreach(@outputpcaps)
	{
        	#unlink($_);
	}
}

sub doAt{	
	@filelist=(findBuffers("$timestamp", "$eachway"));
	if ($verbose) {
		print " Running in doAt mode \n";
		print " ----- Extract will be performed against the following files -----\n";
	        foreach (@filelist){
        	        print " - $_\n";
        	}
		print " -----/ File Roster ------\n";
	}
	my $bpf=mkBPF();
	doExtract($bpf);
}


sub doEvent{
	if ($verbose) {
		print " ----- Running in doEvent mode (input from log file)----- \n";
	}
	my $logline=shift;

	my %eventdata = (); 

	# Work through a list of file-parsers until we get a hit	
	while (1) {
        	%eventdata=ofpcParse::SF49IPS($logline); if ($eventdata{'parsed'} ) { last; }
        	%eventdata=ofpcParse::Exim4($logline); if ($eventdata{'parsed'} ) { last; }
        	%eventdata=ofpcParse::SnortSyslog($logline); if ($eventdata{'parsed'} ) { last; }
        	die("Unable to parse this log line. It Doesn't match any of my parsers. Sorry!")
	}

	if ($verbose) {
		print "---Decoded Event---\n" .
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
		&showerror("Date requested is outside the range of the packet in buffer - We don't have it. \nCould the event be in another set of files? Consider --all\n");
	
	}

	if ($eventdata{'timestamp'} > $now) {
		showerror("Historical date requested is in the future. Clearly you have a ntp problem.");
	}
	#my $bpf = "foo";
	my $bpf="host $eventdata{'sip'} and host $eventdata{'dip'} and port $eventdata{'spt'} and port $eventdata{'dpt'}";
	@filelist=(findBuffers("$timestamp", "$eachway"));
	doExtract($bpf);	
	
}

sub doInit{
	# Do the stuff that's required regardless of mode of operation

	open (CURRENT_FILE,"$config{'CURRENT_FILE'}") or showerror("Unable to open current file \"$config{'CURRENT_FILE'}\". Have you got a buffer running?");
	while (my $line = <CURRENT_FILE>){
        	$currentRun=$line;
        	chomp($currentRun);
		if ($verbose) {
			print " - Current running buffer suffix is $currentRun\n";
		}
	}
	close (CURRENT_FILE);
	my @pcaptemp = `ls -rt $config{'BUFFER_PATH'}/buffer.$currentRun-*`;
	foreach(@pcaptemp) {
        	chomp $_;
        	push(@PCAPS,$_);
	}
	
	# Check that we are asking for data from a window we have in the buffer
	if (($firstpacket)=split(/ /,`$config{'TCPDUMP'} -n -tt -r $PCAPS[0] -c 1 2>/dev/null`)) {
        	if ( $verbose ) {
	                my $firstpacket_localtime=localtime($firstpacket);
        	        my $localtime = localtime();
                	print " - First buffer found is  : $PCAPS[0]\n";
                	print " - First packet in buffer : $firstpacket_localtime\n";
                	print " - Local time is now      : $localtime\n";
        	}
	} else {
        	print "Problem accessing $PCAPS[0]\n Without a buffer I cant continue";
        	exit 1;
	}
}

################# Start processing here ####################

print STDERR "
	* ofpc-extract.pl  - Part of the OpenFPC (Full Packet Capture)
	  Leon Ward - leon\@rm-rf.co.uk\n\n";

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
if ($verbose) {
	print "* Dumping options \n" .
		"   timestamp = $timestamp \n" .
		"   mode = $mode \n" .
		"   event = $event \n" .
		"   src_addr = $src_addr \n" .
		"   dst_addr = $dst_addr \n" .
		"   src_port = $src_port \n" .
		"   dst_port = $dst_port \n" .
		"   eachway  = $eachway \n" .
		"   write    = $outputFile \n" .
		"   Starttime = $startTime (". localtime($startTime) . ") \n" .
		"   Endtime   = $endTime (". localtime($endTime) . ")\n" ;
}

##### Decide what to do.

if ($help) {
	usage;
	exit 0;
}

if ( ($mode eq "window") or ($mode eq "w") or ($startTime and $endTime)) {
	if ($verbose) {
		print "*  Running in window search mode\n";
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
		print STDERR " - Warning: Timestamp not specified, Assuming \"now\" of " . localtime($now) ." \n";
	}
	if ($sf) {	
		if ($verbose) {
			print " - Got timestamp in SF format \"$timestamp\"\n";
		}

        	my $epoch=`date --date='$timestamp' +%s` or showerror("Unable to convert SF format timestamp $timestamp to epoch. Are you sure its valid");
        	chomp $epoch;
		$timestamp=$epoch;
		if ($verbose) {
			print " - Converted SF timestamp to $timestamp\n";
		}	
	}
	doInit;
	
	my $request_time = localtime($timestamp);
	if ($verbose) {
        	print " - Event requested is     : $request_time\n";
	}
	if (($timestamp < $firstpacket) or ($timestamp > time())) {
        	&showerror("Date requested is outside the range of the packet in buffer - We don't have it. \nCould the event be in another set of files? Consider --all\n");
        	exit 1;
	}
	doAt;
} elsif ($event) {
	if ($verbose) {
		print "Running in Event mode\n";	
	}
	doInit;
	doEvent($event);
} else {
	print STDERR "Error, You need to tell me what to do!\n";
	print STDERR "Take a look at --help\n";
	exit 1;
}


