#!/bin/bash -e

# Quickly test a set of functions to ensure things work before rolling a release

# Leon Ward - leon@rm-rf.co.uk


TARPATH=~
SRCPATH=..
USER="admin";		# Creds to use for this one tes
PASS="admin";
OFPC="openfpc-client -u $USER -p $PASS"
IP=$(hostname --all-ip-addresses)

echo IP is $IP
echo -e "[*] Checking Functions. Have you SVN up and installed? <Press Enter>"
read foo

if [ "$1" == "install" ] 
then
	echo "[-] About to reinstall <ENTER>"
	read foo
	cd ..	
	echo " - Reinstalling ..."
	sudo ./openfpc-install.sh reinstall > /dev/null
	cd tools
	sudo openfpc -a stop  -q
	sudo openfpc -a start -q
	echo "[------------------------------]"
	sudo openfpc -a status -q
	echo "[------------------------------]"
fi

SUMTYPE="top_source_ip_by_connection
	top_source_ip_by_volume
	top_destination_ip_by_connection
	top_destination_ip_by_volume
	top_source_tcp_by_connection
	top_source_tcp_by_volume
	top_destination_tcp_by_connection
	top_destination_tcp_by_volume
	top_destination_udp_by_connection
	top_destination_udp_by_volume
	top_source_udp_by_connection
	top_source_udp_by_volume"

echo [-] Summary Tables
ARGS="-a summary --summary_type"

for T in $SUMTYPE
do
	CMD="$OFPC $ARGS $T"
	echo " -  Table: $T"
	$CMD > /dev/null || echo "ERROR Running $CMD"
done

echo [-] Search Tests

SEARCH="--sip $IP
	--dip $IP
	--spt 53
	--dpt 80"
ARGS="-a search --limit 5 --last 6000"

$OFPC $ARGS --dip $IP || echo "ERROR with $OFPC $ARGS --dip $IP"
$OFPC $ARGS --sip $IP > /dev/null || echo "ERROR with $OFPC $ARGS --sip $IP "
$OFPC $ARGS --dpt 80 > /dev/null || echo "ERROR with $OFPC $ARGS --dpt 80"
$OFPC $ARGS --spt 53 > /dev/null || echo "ERROR with $OFPC $ARGS --spt 53"

echo [-] Fetch PCAP

ARGS="-a fetch --dip $IP --last 600"
$OFPC $ARGS -q
$OFPC $ARGS -q --zip --comment "Testing"

echo [-] Storing pcaps
ARGS="-a store --dip $IP --last 60"
$OFPC $ARGS 
ARGS="-a store --dpt 80 --last 60"
$OFPC $ARGS 







