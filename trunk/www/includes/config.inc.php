<?php
# --------------------------------------------------------------------------
# Copyright (C) 2011 Edward Fjellskål <edward.fjellskaal@gmail.com> and
# Leon Ward <leon@rm-rf.co.uk>
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

// Read in configuration from openfpc.conf. Set this to the instance you want to use
$configfile="/etc/openfpc/openfpc-default.conf";
# --------------------------------------------------------------------------
// Nothing to do below this line.
$debug = 1;
$utc_offset=0;
$timezone="UTC";

$file = fopen($configfile, "r");
$openfpcver=0.5;

// Save config and users into an array
while ( $line = fgets($file, 200) ) {
	if ( preg_match("/^USER/", "$line")) {
		list ($tmp,$user,$pass) = (explode("=",$line));
		$users["$user"] = $pass;
	}

	if (preg_match("/^[A-Z]/", $line)) {
		list ($configkey,$configval) = (explode("=",$line));
		chop($configval);
		$config["$configkey"] = $configval;
	}
}
fclose($file);

// openfpc Database Settings
$dbhost = "127.0.0.1";
$dbuser = "openfpc";
$dbname = "openfpc";
$dbpass = "openfpc";

if ($config["SESSION_DB_NAME"]) $dbname = $config["SESSION_DB_NAME"];
if ($config["SESSION_DB_USER"]) $dbuser =  $config["SESSION_DB_USER"] ;
if ($config["SESSION_DB_PASS"]) $dbpass =  $config["SESSION_DB_PASS"] ;
if ( preg_match("/^[+-]\d+/", $config["UTC_OFFSET"])) {
	$utc_offset =  $config["UTC_OFFSET"];
}
if ( preg_match("/^[A-Z]../", $config["TIMEZONE"])) {
	$timezone =  $config["TIMEZONE"];
}


//OFPC Queue Daemon Settings
$ofpcuser = "openfpc";
$ofpcpass = "openfpc";
 
if ($config["GUIUSER"])  $ofpcuser=$config["GUIUSER"]  ;
if ($config["GUIPASS"])  $ofpcpass=$config["GUIPASS"]  ;

// Settings
$maxRows = 100;
$ofpc_client = "openfpc-client";
