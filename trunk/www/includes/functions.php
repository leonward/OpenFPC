<?php
# --------------------------------------------------------------------------
# Copyright (C) 2010 Edward Fjellskål <edward.fjellskaal@gmail.com>
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

// Functions

function convertDateTime($dateTime, $oldDateTimeZone, $newDateTimeZone ){
    global $tzonelocal;
    # Create the timezone objects
    $tzoneOld = new DateTimeZone($oldDateTimeZone);
    $tzoneNew = new DateTimeZone($newDateTimeZone);

    # Create the DateTime object
    $dateTime = new DateTime($dateTime, $tzoneOld);

    # Change the timezone
    $dateTime->setTimezone($tzoneNew);
    
    # Set the format, and ret
    return $dateTime->format('Y-m-d H:i:s');
}


function doSessionQuery() {
    global $cxtid, $ipv, $sessp, $debug;
    if ($debug) {print "doSessionQuery got: $cxtid, $ipv, $sessp <br>" ; };
    $siteDB = new siteDB();
    //$ipv=$sessp;
    
    if ( $sessp == 2 ) {
        $query = "SELECT sessionid, start_time,end_time,
                 inet_ntoa(src_ip) as src_ip,src_port,
                     inet_ntoa(dst_ip) as dst_ip,dst_port,
                 ip_proto
              FROM session
              WHERE sessionid = '$cxtid' limit 1;";
    }
    else if ( $sessp == 10 ) {
        $query = "SELECT sessionid, start_time,end_time,
                                 inet_ntoa6(src_ip) as src_ip,src_port,
                                 inet_ntoa6(dst_ip) as dst_ip,dst_port,
                                 ip_proto
                          FROM session
                          WHERE sessionid = '$cxtid' limit 1;";
    } else {
       // Bugfix to prevent this from attempting to fire when a search for sessions is performed.
       return nil;
    }
        $siteQ = $siteDB->query($query);
        for ($i = 0; $row = mysql_fetch_row($siteQ); $i++) {

                for ($p = 0; $p < count($row); $p++) {
                        $array[mysql_field_name($siteQ, $p)] = $row[$p];
                }
                //$out .= "<div class=eventBox \">" . eventRowFormat($array) . "</div>";
                //unset($array);
        }
        $siteDB->close();

        return $array;
}

function doSearchQuery() {
    global $maxRows, $srcip, $dstip, $srcport, $dstport, $start_date, $end_date, $debug;
    global $protocol, $ipv, $notsrcip, $notdstip, $notsrcport, $notdstport, $tzonelocal;
    $out="";
    $siteDB = new siteDB();
    $orderBy = "start_time";

    # Change user supplied DateTime's to GMT before querying cxtracker DB
    //$start_date = convertDateTime($start_date, $tzonelocal, 'GMT');
    //$end_date = convertDateTime($end_date, $tzonelocal, 'GMT'); 

    # USer specific TZ set in user record 
    # Change user supplied DateTime's to GMT before querying cxtracker DB
    $start_date = convertDateTime($start_date, $_SESSION['timezone'], 'GMT');
    $end_date = convertDateTime($end_date, $_SESSION['timezone'], 'GMT'); 

    //if ( preg_match("/^(\d){1,2}$/",$ipv) ) {
    //  if ( $ipv != 2 || $ipv != 10 || $ipv !=12 ) $ipv = 12; 
    //}
    if ($protocol == "any") $protocol = "";

    if ($debug) { print "SRC_IP is $srcip<br>" ; }
    if ($debug) { print "DST_IP is $dstip<br>" ; }

    $query = "";
    if ( $ipv == 2 || $ipv == 12 ) {
            $query = "select sid,sessionid,start_time,end_time,inet_ntoa(src_ip) as src_ip,
              src_port,inet_ntoa(dst_ip) as dst_ip,dst_port,ip_proto,ip_version,
              src_pkts,src_bytes,dst_pkts,dst_bytes,src_flags,dst_flags,duration
                          from session where 
                      start_time > '$start_date' and end_time < '$end_date' and ip_version='2' ";
        if ($ipv == 12) $srcip = $dstip = "";
        if (!empty($srcip) && isip4($srcip)) {
            $query .= "and src_ip ";
            if ($notsrcip) $query .= "!";
            $query .= "= inet_aton('$srcip') ";
        }
        if (!empty($dstip) && isip4($dstip)) {
            $query .= "and dst_ip ";
            if ($notdstip) $query .= "!";
            $query .= "= inet_aton('$dstip') ";
        }
        if (!empty($srcport) && isport($srcport)) {
            $query .= "and src_port ";
            if ($notsrcport) $query .= "!";
            $query .= "= '$srcport' ";
        }
        if (!empty($dstport) && isport($dstport)) {
            $query .= "and dst_port ";
            if ($notdstport) $query .= "!";
            $query .= "= '$dstport' ";
        }
        if (!empty($protocol) && isprotocol($protocol)) $query .= "and ip_proto = '$protocol' ";

        if ( $ipv != 12 ) $query .= "ORDER BY $orderBy DESC limit $maxRows;";
    }

    if ( $ipv == 12 ) $query .= " union ";

    if ( $ipv == 10 || $ipv == 12 ) {
        if ($protocol == 1) $protocol = 58;
        $query .= "select sid,sessionid,start_time,end_time,inet_ntoa6(src_ip) as src_ip,
               src_port,inet_ntoa6(dst_ip) as dst_ip,dst_port,ip_proto,ip_version,
               src_pkts,src_bytes,dst_pkts,dst_bytes,src_flags,dst_flags,duration
                       from session where
                       start_time > '$start_date' and ip_version='10' ";
        if ($ipv == 12) $srcip = $dstip = "";
        if (!empty($srcip) && isip6($srcip)) { 
            $query .= "and src_ip ";
            if ($notsrcip) $query .= "!";
            $query .= "= inet_aton6('$srcip') ";
        }
        if (!empty($dstip) && isip6($dstip)) {
            $query .= "and dst_ip ";
            if ($notdstip) $query .= "!";
            $query .= "= inet_aton6('$dstip') ";
        }
        if (!empty($srcport)) {
            $query .= "and src_port ";
            if ($notsrcport) $query .= "!";
            $query .= "= '$srcport' ";
        }
        if (!empty($dstport)) {
            $query .= "and dst_port ";
            if ($notdstport) $query .= "!";
            $query .= "= '$dstport' ";
        }
        if (!empty($protocol)) $query .= "and ip_proto = '$protocol' ";

        $query .= "ORDER BY $orderBy DESC limit $maxRows;";
    }

	if ($debug) { print "Query is $query<br>" ; }
        $siteQ = $siteDB->query($query);


        for ($i = 0; $row = mysql_fetch_row($siteQ); $i++) {
            for ($p = 0; $p < count($row); $p++) {
			if (mysql_field_name($siteQ, $p) == "start_time" || mysql_field_name($siteQ, $p) == "end_time")
			{
                                # Change the DB records datetime from GMT to local
#                                $dateTime = convertDateTime($row[$p], 'GMT', $tzonelocal);
                                $dateTime = convertDateTime($row[$p], 'GMT', $_SESSION['timezone']);
				$array[mysql_field_name($siteQ, $p)] = $dateTime;
			} else {
                                $array[mysql_field_name($siteQ, $p)] = $row[$p];
			}
            }
            $out .= eventRowFormat($array);
            unset($array);
        }

        $siteDB->close();

        return $out;
}

function eventRowFormat($data) {
    $out = "";

    $out .= "<tr onmouseover=\"this.style.cursor=&#39;hand&#39;\" ";
    $out .= "onclick=\"SessionWindow('" . $data["sessionid"] . "','" . $data["ip_version"] .  "');\"";
    $out .= ">";
    // Sensor
    //$out .= "<td onmouseover=\"this.style.cursor=&#39;hand&#39;\" onclick=\"SessionWindow('" . $data["sessionid"] . "','" . $data["ip_version"] . "');\">" . $data["sessionid"] . "</td>";
    //$out .= "<td>" . $data["sessionid"] . "</td>";

    // Source IP
    $out .= "<td>" . $data["src_ip"] . "</td>";

    // Source PORT
    $out .= "<td>";
    if ($data["src_port"]) {
        $out .= $data["src_port"];
    } else {
        $out .= "0";
    }
    $out .= "</td>";

    // Destination IP
    $out .= "<td>" . $data["dst_ip"] . "</td>";

    // Destination PORT
    $out .= "<td>";
    if ($data["dst_port"]) {
        $out .= $data["dst_port"];
    } else {
        $out .= "0";
    }
    $out .= "</td>";
    
    // Protocol
    $out .= "<td>" . $data["ip_proto"] . "</td>";

    // Duration
    $out .= "<td>";
    if ($data["duration"]) {
        $out .= $data["duration"];
    } else {
        $out .= "0";
    }
    $out .= "</td>";

    // Src_pkts
    $out .= "<td>" . $data["src_pkts"] . "</td>";

    // Dst_pkts
    $out .= "<td>" . $data["dst_pkts"] . "</td>";

    // Src_bytes
    $out .= "<td>" . $data["src_bytes"] . "</td>";

    // Dst_bytes
    $out .= "<td>" . $data["dst_bytes"] . "</td>";

    // Src_flags
    $out .= "<td>" . tftoa($data["src_flags"]) . "</td>";

    // Dst_flags
    $out .= "<td>" . tftoa($data["dst_flags"]) . "</td>";

    // Time info col
    $out .= "<td>" . $data["start_time"] . "</td>";
    $out .= "<td>" . $data["end_time"] . "</td>";

    $out .= "</tr>";

    return $out;
    
}

// Support Functions

function pollParse($data) {

    $obj = getVar("obj");
    if (empty($obj)) $obj = "object1";

    header ("Content-type: text/javascript");

    echo "document.getElementById('$obj').innerHTML='$data';";

    unset($data, $obj);
}

// tcp Flags to ascii
function tftoa($flags) {
    $out = "";
    
    if ( $flags & 0x01 ) $out .= "F";
    if ( $flags & 0x02 ) $out .= "S";
    if ( $flags & 0x04 ) $out .= "R";
    if ( $flags & 0x08 ) $out .= "P";
    if ( $flags & 0x10 ) $out .= "A";
    if ( $flags & 0x20 ) $out .= "U";
    if ( $flags & 0x40 ) $out .= "E";
    if ( $flags & 0x80 ) $out .= "C";

    if ( $out == "" ) $out .= "-";
    return $out;
}

// ascii to tcp Flags
function atotf($in) {
        $flags = 0x00;

    if (preg_match("/F/",$in)) $flags = $flags | 0x01;
    if (preg_match("/S/",$in)) $flags = $flags | 0x02;
    if (preg_match("/R/",$in)) $flags = $flags | 0x04;
    if (preg_match("/P/",$in)) $flags = $flags | 0x08;
    if (preg_match("/A/",$in)) $flags = $flags | 0x10;
    if (preg_match("/U/",$in)) $flags = $flags | 0x20;
    if (preg_match("/E/",$in)) $flags = $flags | 0x40;
    if (preg_match("/C/",$in)) $flags = $flags | 0x80;

        return $flags;
}

function backdate($days) {
        $backdate = mktime(0, 0, 0, date("m"), date("d")-$days, date("y"));
        return date("Y-m-d", $backdate);
}

function forwarddate($days) {
        $backdate = mktime(0, 0, 0, date("m"), date("d")+$days, date("y"));
        return date("Y-m-d", $backdate);
}

function sanitize($in) {
    return strip_tags(addslashes(getVar($in)));
}

function valdate($sd) {
    // 2009-12-22 18:44:35
    if (preg_match("/^(\d\d\d\d)-(\d\d)-(\d\d)( \d\d:\d\d:\d\d)?$/",$sd,$array)) {
        if(checkdate($array[2],$array[3],$array[1])) {
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

function is_not_set($string) {
    // !192.168.0.1 or !443
    if (preg_match("/^!/",$string)) {
        return true;
    } else {
        return false;
    }
}

function strip_not($string) {
    // !192.168.0.1 or !443
    if (preg_match("/^(!)(.*)/",$string,$array)) {
                return $array[2];
        } else {
                return $string;
        }
}

function dirdate($dd) {
    // 2009-12-22
    if (preg_match("/^(\d\d\d\d)-(\d\d)-(\d\d)/",$dd,$array)) {
        $out = $array[1] . "-" . $array[2] . "-" . $array[3];
        return $out;
    } else {
        return false;
    }
}

function dd2unix($dd){
    if (preg_match("/^(\d\d\d\d)-(\d\d)-(\d\d)/",$dd,$array)) {
        return mktime (0, 0, 0, $array[2], $array[3], $array[1]);
    }
}

function isport($port) {
    // 0 - 65535
    if (preg_match("/^([\d]){1,5}$/",$port) && $port >= 0 && $port <= 65535) {
        return true;
    } else {
        return false;
    }
}

function isprotocol($protocol) {
    // 0 - 255
    if (preg_match("/^([\d]){1,3}$/",$protocol) && $protocol >= 0 && $protocol <= 255) {
                return true;
        } else {
                return false;
        }
}

function isip4($ip) {
        // ddd.ddd.ddd.ddd
        if (substr_count($ip,".") == 3) {
                if (preg_match("/^([\d]{1,3}\.){3}[\d]{1,3}$/",$ip)) {
                     return true;
                }
        } else {
                return false;
        }
}

function isip6($ip) {
        // hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh:hhhh
        if (substr_count($ip,":") > 1 && substr_count($ip,":") < 8 && substr_count($ip,".") == 0){
                $uip = uncompress_ipv6($ip);
                if (!ereg('^:',$uip) && !ereg(':$',$uip) && !ereg('::',$uip) ) {
                        if ( preg_match("/^([a-f\d]{4}:){7}[a-f\d]{4}$/",$uip) ) {
                                return true;
                        }
                }
        } else {
                return false;
        } 
}

function uncompress_ipv6($ip ="") {
    if(strstr($ip,"::" )) {
        $e = explode(":", $ip);
        $s = 8-sizeof($e);
        foreach ($e as $key=>$val) {
                if ($val == "") {
                    for($i==0;$i<=$s;$i++) {
                        $newip[] = "0000";
                }
                } else {
                    $newip[] = $val;
                }
        }
        $ip = implode(":", $newip);
    }
    return $ip;
} 

function getVar($in) {

    if (isset($_POST[$in])) {
        $out = $_POST[$in];
    } else {
        $out = $_GET[$in];
    }
    
    if (get_magic_quotes_gpc()) {
        if (is_array($out)) {
            foreach ($out as $el) {
                $array[] = stripslashes($el);
            }
            $out = $array;
        } else {
            $out = stripslashes($out);
        }    
    }
        
    return $out;
}

function list_pcaps_in_dir($_dir) {
    if (is_dir($_dir)) {
        $files = scandir($_dir);
        $i = 0;
        $array[$i] = "";
        foreach($files as $key => $file){
            $dirfile =  "$_dir" . "$file";
            if (is_file("$dirfile")) {
                $cmd = escapeshellcmd($dirfile);
                $output = shell_exec("file \"$cmd\"");
                if (is_file_pcap("$output")) {
                    $array[$i] = $file;
                    $i++;
                }
            }
        }
        return $array[$i];
    } else {
        return false;
    }
}

function is_file_pcap($_file) {
    // " tcpdump capture file "
    if (preg_match("/ tcpdump capture file /",$_file)) {
        return true;
    } else {
        return false;
    }
}

function serv_pcap($filepath,$cxid) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/pcap-capture');
    header("Content-Disposition: attachment; filename=$cxid");
    header('Content-Transfer-Encoding: binary');
    header('Expires: 0');
    header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
    header('Pragma: public');
    header('Content-Length: ' . filesize($filepath));
    ob_clean();
    flush();
    readfile($filepath);
    exit;
}

# Return unix timestamp including seconds.
function stime2unix($stime){
    if (preg_match("/^(\d\d\d\d)-(\d\d)-(\d\d)\s(\d+):(\d+):(\d+)/",$stime, $array)) {
        return mktime ($array[4], $array[5], $array[6], $array[2], $array[3], $array[1]);
    } else {
        return(0);
    }
}

function guiDB(){
    global $guidbhost, $guidbuser, $guidbpass, $guidbname, $debug;

    if ($debug){
        print "GUIDB PASS is \"$guidbpass\"<br>\n";
        print "GUIDB USER is \"$guidbuser\"<br>\n";
        print "GUIDB name is \"$guidbname\"<br>\n";
        print "GUIDB host is \"$guidbhost\"<br>\n";
    }
    
    ($guilink = mysql_pconnect("$guidbhost", "$guidbuser", "$guidbpass")) || errorpage("Can't connect to GUIDB Host: $guidbhost Pass: $guidbpass DB: $guidbname User $guidbuser foo" . mysql_error() . "Have you run openfpc-dbmaint to create and set up your GUI database?");
    mysql_select_db("$guidbname", $guilink) || die("Cant open $guidbname.".mysql_error()."<br>Have you created a GUI db using openfpc-dbmaint and set the GUI_DB_USER/GUI_DB_PASS in your openfpc config file?" );
    return($guilink);
}

function infobox($infomsg) {
	$out = "<!-- infoBox -->\n";
	$out .= "<div class=\"span-20\">";
	$out .= $infomsg;
	$out .= "<!-- /infoBox -->\n";
	$out .= "</div>";
	return $out;
}

class siteDB {
    function siteDB() {
        global $dbhost, $dbuser, $dbpass, $dbname, $debug;

        $this->host = chop($dbhost);
        $this->db   = chop($dbname);
        $this->user = chop($dbuser);
        $this->pass = chop($dbpass);
        $this->link = mysql_connect($this->host, $this->user, $this->pass, 1);

        $connected = mysql_select_db($this->db);
        if (!$connected) {
		if ($debug) print "Error unable to connect to Database!";
	}

    }

    function query($query) {
        
        if ($result = @mysql_query($query, $this->link)) {
            return $result;
        }
    }

    function close() {
        
        @mysql_close($this->link);
    }
}

function checkauth(){
    session_start();
    // Only allow new users to be added if we have auth...
    if ($_SESSION['auth'] != 1) {
	header ("Location: login.php");
    } 
}

function errorpage($message){
    include "includes/header.php";
    $out .= infobox("Error: $message");
    echo $out;
}
?>
