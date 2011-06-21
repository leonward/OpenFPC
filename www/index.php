<?php
# --------------------------------------------------------------------------
# Copyright (C) 2010 
# Edward Fjellskål <edward.fjellskaal@gmail.com>
# Dave Lowe <seclistinbox@gmail.com>
# Leon Ward <leon@openfpc.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# --------------------------------------------------------------------------

require "includes/functions.php";
require "includes/config.inc.php";

session_start();
checkauth();

// Variable Initialization
$op         = sanitize("op");         if (empty($op))         $op = "search";
$ipv        = sanitize("ipv");        if (empty($ipv))        $ipv = "2";
$cxtid      = sanitize("cxtid");      if (empty($cxtid))      $cxtid = "";
$sessp      = sanitize("sessp");      if (empty($sessp))      $sessp = "";
$srcip      = sanitize("srcip");      if (empty($srcip))      $srcip = "";
$dstip      = sanitize("dstip");      if (empty($dstip))      $dstip = "";
$srcport    = sanitize("srcport");    if (empty($srcport))    $srcport = "";
$dstport    = sanitize("dstport");    if (empty($dstport))    $dstport = "";
$start_date = sanitize("start_date"); if (!valdate($start_date)) $start_date = date("Y-m-d 00:00:00");
$end_date   = sanitize("end_date");   if (!valdate($end_date))   $end_date   = date("Y-m-d H:i:s");
$protocol   = sanitize("protocol");   if (empty($protocol))   $protocol = "any";
$logline    = sanitize("logline");    if (empty($logline))    $logline = "";
$comment    = sanitize("comment");    if (empty($comment))    $comment = "No Comment";
$bpf        = sanitize("bpf");        if (empty($bpf))        $bpf= "bpf";

$out="";

$notsrcip = 0; if (is_not_set($srcip)) $notsrcip = 1;
$notdstip = 0; if (is_not_set($dstip)) $notdstip = 1;
$notsrcport  = 0; if (is_not_set($srcport)) $notsrcport = 1;
$notdstport  = 0; if (is_not_set($dstport)) $notdstport = 1;
if ($notsrcip) $srcip = strip_not($srcip);
if ($notdstip) $dstip = strip_not($dstip);
if ($notsrcport)  $srcport = strip_not($srcport);
if ($notdstport)  $dstport = strip_not($dstport);

// Dump some debug output
if ($debug) {
	print "DEBUG ENABLED: PCAPS will be b0rked in debug mode!<br>";
	print "Version is $openfpcver<br>";
	print "dbuser is $dbuser<br>" ;
	print "db is $dbname<br>";
	print "dbpass is $dbpass<br>";
	print "openfpcuser is $ofpcuser<br>";
	print "openfpcpass is $ofpcpass<br>";
	print "Timezone is $timezone<br>";
	print "User tz is " . $_SESSION['timezone'] . "<br>";
	print "BPF is $bpf<br>";
	print "Enable Session is $enable_session<br>";
	print "Username is " . $_SESSION['username'] ." <br>";
	//print "Password is ". $_SESSION['password'] . "<br>";
}

// OP Director
switch ($op) {

    // Search has been submitted for sessions
    case "Search Sessions":
	include "includes/searchDisplay.php";
        $out .= showResults();
        $data = doSessionQuery(); 
        break;

    // Display a page to allow a user to get full pcap data via constraints
    case "Extract pcap":
	include "includes/extractDisplay.php";
        $out .= extractPcapFromSearch();	
        break;

    // Action taken when a table-result is clicked	
    case "dump":
        $out = extractPcapFromSession();
        #$out .= showResults();
        #$out = dumpDisplay();   
        break;

    case "Search Sessions":
	include "includes/searchDisplay.php";
        break;

    case "Store pcap from event":
        include "includes/logLine.php";
        $out = extractPcapFromLog("store");
        break;

    // Display a page to allow a user to enter a BPF
    case "Fetch pcap from BPF":
	include "includes/bpf.php";
	$out .= extractPcapFromBPF("fetch");
	break;

    // Display from to grab pcaps from event/log line
    case "DisplayLogLine":
        include "includes/logLine.php";
	break;

    case "DisplayBPF":
        include "includes/bpf.php";
	break;

    case "Fetch pcap from event":
        include "includes/logLine.php";
        $out .= extractPcapFromLog("fetch");
        break;
    
    case "about":
        include "includes/about.php";
        break;

    case "guide":
        include "includes/guide.php";
        break;

    default:
        include "includes/extractDisplay.php";
      #  $out .= extractPcapFromSearch();	
        break;
}

include "includes/header.php";
include "includes/menu.php";
echo $out; 
include "includes/footer.php";

// Operational Functions
function showResults() {
    // Show results    
    $out = "<table summary=\"This is the summary text for this table.\"  border=\"0\" cellspacing=\"0\" cellpadding=\"0\">\n";
    $out .= "  <caption>\n";
    $out .= "  <em>OpenFPC Search Results</em>\n";
    $out .= "  </caption>\n";
    $out .= "  <thead>\n";
    $out .= "    <tr>\n";
    //$out .= "      <th class=\"span-4\">cxtID</th>\n";
    $out .= "      <th class=\"span-4\">Src IP</th>\n";
    $out .= "      <th class=\"span-4\">Src Port</th>\n";
    $out .= "      <th class=\"span-4\">Dst IP</th>\n";
    $out .= "      <th class=\"span-4\">Dst Port</th>\n";
    $out .= "      <th class=\"span-4\">Protocol</th>\n";
    $out .= "      <th class=\"span-4\">Duration</th>\n";
    $out .= "      <th class=\"span-4\">Src Pkts</th>\n";
    $out .= "      <th class=\"span-4\">Dst Pkts</th>\n";
    $out .= "      <th class=\"span-4\">Src Bytes</th>\n";
    $out .= "      <th class=\"span-4\">Dst Bytes</th>\n";
    $out .= "      <th class=\"span-4\">Src Flags</th>\n";
    $out .= "      <th class=\"span-4\">Dst Flags</th>\n";
    $out .= "      <th class=\"span-4\">Start Time</th>\n";
    $out .= "      <th class=\"span-4 last\">End Time</th>\n";
    $out .= "    </tr>\n";
    $out .= "  </thead>\n";
    $out .= "  <tfoot>\n";
    $out .= "    <tr>\n";
    $out .= "      <td colspan=\"15\">Table listing results of OpenFPC search</td>\n";
    $out .= "    </tr>\n";
    $out .= "  </tfoot>\n";
    $out .= "  <tbody>\n";
    $out .= doSearchQuery();
    $out .= "  </tbody>\n";
    $out .= "</table>\n";
    $out .= "</div>\n";
    return $out;
}

# Calls ofpc-client.pl to extract the data if the user enters a "log" line.
function extractPcapFromBPF($action) {
	global $bpf, $comment, $ofpc_client, $debug;

	$out = "<!-- extractPcapFromBPF -->\n";

	# Shell out to ofpc-client here. Note the --gui option.
	$exec = "$ofpc_client -u " . $_SESSION[username] . " -p " . $_SESSION[password] . " --gui ";
	$exec .= "-a $action ";
	$exec .= "--bpf \"$bpf\" ";
	$exec .= "--comment \"$comment\" ";

	# Clean up command before we exec it.
	$e = escapeshellcmd($exec);

	# These are defined in ofpc-client.pl
	if ($debug) { print "Exec is $e<br>"; }
	$cmdresult = shell_exec($e);
	list($result,$action,$filename,$size,$md5,$expected_md5,$position,$message) = explode(",",$cmdresult);

	$pathfile=explode("/",$filename);	# Break path and filename from filename
	$file=array_pop($pathfile);		# Pop last element of path/file array

	if ($result) {
		if ($action == "store" ) {
			$infomsg .= "Extract in queue position $position.<br>\n";
			$infomsg .= "Expected filename: $file.<br>\n";
			$out .= infoBox($infomsg);	
		} elseif ( $action == "fetch") {
			serv_pcap("$filename","$file");
			exit(0);
		}
	} else {
		$infomsg = "Error: $message<br>";
		$out .= infoBox($infomsg);
	}
	$out .= "<!-- /extractPcapFromBPF -->\n";
	return $out;
}

# Calls ofpc-client.pl to extract the data if the user enters a "log" line.
function extractPcapFromLog($action) {
	global $logline, $ofpcuser, $ofpcpass, $comment, $ofpc_client, $debug;

	$out = "<!-- extractPcapFromLog -->\n";

	# Shell out to ofpc-client here. Note the --gui option.
	$exec = "$ofpc_client -u " . $_SESSION[username] . " -p " . $_SESSION[password] . " --gui ";
	$exec .= "-a $action ";
	$exec .= "--logline \"$logline\" ";
	$exec .= "--comment \"$comment\" ";

	# Clean up command before we exec it.
	$e = escapeshellcmd($exec);

	# These are defined in ofpc-client.pl
	if ($debug) { print "Exec is $e<br>"; }
	$cmdresult = shell_exec($e);
	list($result,$action,$filename,$size,$md5,$expected_md5,$position,$message) = explode(",",$cmdresult);

	$pathfile=explode("/",$filename);	# Break path and filename from filename
	$file=array_pop($pathfile);		# Pop last element of path/file array

	if ($result) {
		if ($action == "store" ) {
			$infomsg .= "Extract in queue position $position.<br>\n";
			$infomsg .= "Expected filename: $file.<br>\n";
			$out .= infoBox($infomsg);	
		} elseif ( $action == "fetch") {
			serv_pcap("$filename","$file");
			exit(0);
		}
	} else {
		$infomsg = "Error: $message<br>";
		if ($debug) { $infomsg .= "$e";}
		$out .= infoBox($infomsg);
	}
	$out .= "<!-- /extractPcapFromLog -->\n";
	return $out;
}

# Calls ofpc-client.pl to extract the traffic when the user selects a session entry in the table

function extractPcapFromSession() {
    global $ofpcuser, $ofpcpass, $ofpc_client, $debug;
	if ($debug) {
		echo "Function: extractPcapFromSession\n";
	}

	$array=doSessionQuery();

        # Change timezones from GMT to Local
        $stime = convertDateTime($array["start_time"], 'GMT', $_SESSION['timezone']);
        $etime = convertDateTime($array["end_time"], 'GMT', $_SESSION['timezone']);
	
	if ($debug) {
		print "Start time of oiginal timestamp is " . $array["start_time"] . "<br>";
		print "Start time converted to local is  $stime <br>";
		print "Converted local in epoch  is " . stime2unix($stime) . "<br>" ;
		print "Start time original in epoch is " . stime2unix($array["start_time"]) . "<br>";
	}
	
	$exec = "$ofpc_client -u " . $_SESSION[username] . " -p " . $_SESSION[password] .
		" --gui " .
		" --stime " . stime2unix($stime) .
		" --etime " . stime2unix($etime) .
		" --src-addr "  . $array["src_ip"] .
		" --dst-addr "  . $array["dst_ip"] .
		" --proto "     . $array["ip_proto"];
		
	# Only add ports if this is tcp / udp
	if ( $array["ip_proto"] == 17 or $array["ip_proto"] == 6 ) { 		
		$exec .= " --src-port "  . $array["src_port"] .
			" --dst-port "  . $array["dst_port"];
	}
	
        if ($debug) { print "openfpc-client CMD: $exec<br>" ; }
	$e = escapeshellcmd($exec);
	$shellresult = shell_exec($e);

	list($result,$action,$filename,$size,$md5,$expected_md5,$position,$message) = explode(",",$shellresult);
	$pathfile=explode("/",$filename);       # Break path and filename from filename 
	$file=array_pop($pathfile);             # Pop last element of path/file array

	if ($debug) {
		print "Not extracting session: Debug enabled<br>";
	} else {
		if ($result) {
			serv_pcap("$filename","$file");
			exit(0);
		} else {
   		    if ($debug) { print "sessions-extract-error: $message<br>" ; }
			$infobox .= "Error: $message <br>";
		}
	}

	$out .= infoBox($infobox);	
	return $out;
}

// The "Extract pcap" button doesn't search the DB for session data, it just extracts as requested.
// Why? Well there are two answers to that. 
// 1) I think there will be times when people don't track connection data (storage, CPU, IO limits)
// 2) On a proxy device, there won't be a central DB to search over. This way a quick extraction can
// take place using the proxy-to-node function.
// -Leon 

function extractPcapFromSearch() {
	global $ofpcuser, $ofpcpass,$ofpc_client, $start_date, $srcip, $dstip, $srcport, $dstport, $protocol, $debug, $end_date;
	
	if ($debug) {
		print "<br>Function: extractPcapFromSearch<br>";
	}


	$exec = "$ofpc_client -u " . $_SESSION[username] . " -p " . $_SESSION[password] . " --gui ";
	$stime = stime2unix($start_date);
	$etime = stime2unix($end_date);

	if ($debug) {
		print "Start date is " . $start_date . " $stime <br> End date is " . $end_date . " $etime<br>";
	}

	if ($start_date) { $exec .= " --stime " . $stime; }
	if ($end_date) { $exec .= " --etime " . $etime; }
	if ($srcip) { $exec .= " --src-addr " . $srcip ; }
	if ($dstip) { $exec .= " --dst-addr " . $dstip ; }
	if ($srcport) { $exec .= " --src-port " . $srcport ; }
	if ($dstport) { $exec .= " --dst-port " . $dstport ; }
	if ($protocol) { $exec .= " --proto " . $protocol ; }

	$e = escapeshellcmd($exec);
	$shellresult = shell_exec($e);

	list($result,$action,$filename,$size,$md5,$expected_md5,$position,$message) = explode(",",$shellresult);
	$pathfile=explode("/",$filename);       # Break path and filename from filename 
	$file=array_pop($pathfile);             # Pop last element of path/file array

	if ($result == 1 ) {
		# Success
		$infobox .= "Success! <br>";
		#$infobox .= "Exec: $exec <br>";
		$infobox .= "MD5: $md5 <br>";
		$infobox .= "Size: $size <br>";
		serv_pcap("$filename","$file");
		exit(0);
	} else {
		# Had an error -
		$infobox .= "Result: $result <br>";
		$infobox .= "Error: $message <br>";
		$infobox .= "Size: $size <br>";
		#$infobox .= "Exec: $exec <br>";
		$infobox .= "Shell result: $shellresult <br>";
	}

	$out .= infoBox($infobox);	
	return $out;
}

