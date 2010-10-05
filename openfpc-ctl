#!/bin/bash 

#########################################################################################
# Copyright (C) 2009 Leon Ward 
# OpenFPC - Part of the OpenFPC - (Full Packet Capture) project
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

# ---------------- Nothing to do below here -------------
# List of config files to try in order

CONFIG_FILES="/etc/openfpc/openfpc.conf ./myopenfpc.conf" 

# Check if we have been passed a config file as $2.
# read the first config file found in order above.

if [ $2 ] 
then
	if [ -f $2 ] 
	then
		CONFIG=$2
		echo "[*] Reading configuration file $CONFIG"
		source $CONFIG
	else
		echo -e "[!] Error: Cant find config file $CONFIG"
		exit 1
	fi 
else 
	for CONFIG in $CONFIG_FILES
	do
		if [ -f $CONFIG ]
		then
			echo "[*] Reading configuration file $CONFIG"
			source $CONFIG
			break
		fi
	done
fi

IAM=$(whoami)
DATE=$(date)
PATH=$PATH:/sbin:/usr/sbin
TCPDUMPOPTS="-Z root" 	
openfpcver=0.2
PID_FILE=openfpc-dl
PID_PATH=/var/run
FILENAME=openfpc-
OPENFPCQD=$INSTALL_DIR/openfpc-queued
CXPIDFILE=/var/run/cxtracker.pid 
CX2DB_PID_FILE="/var/run/openfpc-cx2db.pid"

if [ "$DONE" != "y" ] 
then
	echo -e "[!] Configuration not complete.\n    Have you run ./install-openfpc.sh ?"
	exit 1
fi


if [ "$MULTI_BUFFER" == "1" ] 
then
	CURRENT=$(cat $CURRENT_FILE 2>/dev/null) || CURRENT="SINGLE"
else
	CURRENT="SINGLE"
fi

#sudo tcpdump -n -i eth1 -s 0 -C 50  -W 20 -w /var/tmp/buffer-

function die()
{
	echo $1
	exit 1
}

function clean()
{
	if [ "$IAM" != "root" ]
	then
		die "[!] Must be root"
	fi
	die "! Not done. It's on the todo list"
	# Remove all non-current pcap buffers to free up disk space
	echo [!] Are you sure you want to delete these old pcap buffers?
	RMFILES=$(ls $BUFFER_PATH/$FILENAME* |grep -v $CURRENT)
	echo "$RMFILES"
	echo "---------------"
	read -p "Hit CTRL+C to stop, enter to delete (current buffer will not be affected)"
	rm $RMFILES
}

function openfpcqstart() 
{
	if [ "$IAM" != "root" ]
	then
		die "[!] Must be root"
	fi
	if [ -f $OFPC_Q_PID ] 
	then
		QPID=$(cat $OFPC_Q_PID) || QPID=none
		if ps $QPID > /dev/null 2>&1
		then
			echo -e "[*] OpenFPC Queue Daemon running as Pid: $QPID"
		fi
	else 
		echo -e "[*] Starting OpenFPC Queue Daemon"
		$OPENFPCQD -c $CONFIG --daemon
	  	QPID=$(cat $OFPC_Q_PID) || QPI=none
                if ps $QPID > /dev/null 2>&1
                then
                        echo -e "[-] OpenFPC Queue Daemon running as Pid: $QPID"
                fi  	
	fi	
}

function openfpcqstop()
{
	if [ "$IAM" != "root" ]
	then
		die "[!] Must be root"
	fi
	if [ -f $OFPC_Q_PID ] 
	then
		QPID=$(cat $OFPC_Q_PID) || QPID=none
		if ps $QPID > /dev/null 2>&1
		then
			echo -e "[*] OpenFPC Queue Daemon running as Pid: $QPID"
			kill $QPID
		fi
	else 
		echo -e "[!] OpenFPC Queue Dameon not running"
	fi
}

function cxtrackerstart()
{
	if [ "$IAM" != "root" ]
	then
		die "[!] Must be root"
	fi

	if [ "$PROXY" == 1 ] 
	then
		echo "[*] OpenFPC Proxy mode - Not starting Connection Tracker"
		return
	fi

	if [ $ENABLE_SESSION == 1 ] 
	then
		echo "[*] Session search enabled"
		if [ -f $CXPIDFILE ] 
		then
			CXPID=$(cat $CXPIDFILE)
			if ps $CXPID > /dev/null
			then
				echo -e  "[!] cxtracker already running"
				return
			fi
		fi
		# Check if we have cxtracker 
		if  $CXTRACKER -h > /dev/null  2>&1
		then
			CMD="$CXTRACKER \
				-i $INTERFACE \
				-d $SESSION_DIR \
				-D"
		else
			echo -e "[!] Cant exec cxtracker \"$CXTRACKER\""
			echo -e "    Install cxtracker to enable session search"
			return
		fi

		$CMD
		echo "[*] Starting OpenFPC Connection -> Connection inserter"

		if [ -f $CX2DB_PID_FILE ] 
		then
			CX2DB_PID=$(cat $CX2DB_PID_FILE) || CX2DB_PID=none
			if ps $CX2DB_PID > /dev/null 2>&1
			then
				echo -e "[*] OpenFPC Connection to DB already running as Pid: $CX2DB_PID"
			fi
		fi
			
			openfpc-cx2db.pl --daemon --config $CONFIG
			# Sleep for 2 seconds to make sure we can connect to the local DB
			# TODO: Make cx2db connect to the DB before it daemonizes

			sleep 1 
	  		CX2DB_PID=$(cat $CX2DB_PID_FILE) || CX2DB_PID=none

	                if ps $CX2DB_PID > /dev/null 2>&1
       		       	then
                        	echo -e "[-] OpenFPC Connection -> DB running as Pid: $CX2DB_PID"
                	else   	
                        	echo -e "[!] OpenFPC Connection -> DB FAILED TO START"
			fi
	else 
		echo "[*] Session search disabled on this host"
	fi
}


function cxtrackerstop()
{
	if [ "$IAM" != "root" ]
	then
		die "[!] Must be root"
	fi

	if [ "$PROXY" == 1 ] 
	then
		echo "[*] OpenFPC Proxy mode - Not touching cxtracker" 
		return
	fi


	if [ -f $CXPIDFILE ] 
	then
		CXPID=$(cat $CXPIDFILE)
		if ps $CXPID > /dev/null 
		then
			echo -e "[-] Stopping cxtracker PID $CXPID"
			kill $CXPID
			sleep 1
			if ps $CXPID >/dev/null
			then
				echo -e "[!] Failed to stop CXPID"
			else 
				echo -e "[*] cxtracker Stopped"
			fi
		else 
			echo -e "[*] cxtracker not running"
		fi
	fi
}




function daemonloggerstart()
{
	if [ "$IAM" != "root" ]
	then
		die "[!] Must be root"
	fi
	
	if [ "$PROXY" == 1 ] 
	then
		echo "[*] OpenFPC Proxy mode - Not starting Traffic Buffer"
		return
	fi

	if [ -f $PID_PATH/$PID_FILE ] 
	then
		DPID=$(cat $PID_PATH/$PID_FILE)
		#ps aux |grep $DPID |grep -v grep > /dev/null && die "[!] Daemonlogger already running"
		if ps $DPID  > /dev/null
		then
			echo "[!] Daemonlogger already running"
			return
		fi
	fi 

	if [ -d $BUFFER_PATH ]
	then
		touch $BUFFER_PATH/ok || dir "[!] Cant write to buffer path $BUFFER_PATH."
		rm $BUFFER_PATH/ok || die "Cant remove ok file in buffer path - Strange."
	else
		mkdir --parent $BUFFER_PATH || die "[!] Cant mkdir buffer location $BUFFER_PATH"
	fi
	
	ifconfig $INTERFACE > /dev/null 2>&1 || die "[!] Unable to find device $INTERFACE."
	# It looks like daemonlogger expects to find SOMETHING to unlink in $BUFFER_PATH when it gets 
	# close to -M value. Lets give it a little something, I think this will pevent a lot
	# of questions from confused users. Strange I know, but hey.

	touch $BUFFER_PATH/openfpc-pcap.0
	CMD="$DAEMONLOGGER -d \
		-i $INTERFACE \
		-l $BUFFER_PATH \
		-M $DISK_SPACE \
		-s $FILE_SIZE \
		-p $PID_FILE \
		-P $PID_PATH \
		-n openfpc-$NODENAME-pcap "

	$CMD || die "Unable to start daemonlogger"

	sleep 1
	[ -f $BUFFER_PATH/openfpc-pcap.0 ] && rm $BUFFER_PATH/openfpc-pcap.0
	
	if [ -f $PID_PATH/$PID_FILE ] 
	then
		DPID=$(cat $PID_PATH/$PID_FILE) || die "[!] Error: Unable to read pid file"
		if ps aux |grep $DPID |grep -v grep  > /dev/null
		then
			echo 
			echo "[-] It looks like daemonlogger has started successfully"
		else
			echo
			echo "[!] Error: It looks like something went wrong starting daemonlogger"
			echo "    OpenFPC requires daemonlogger version 1.2.1 or above"
			echo "    You could also try to run the following command to work out what went wrong"
			echo $CMD
		fi
	else 
		die "[!] Error: I don't think daemonlogger is running! No PID file $PID_PATH/$PID_FILE found"
	fi 
	echo "[*] Traffic buffer (Daemonlogger) started on $DATE"
}


function daemonloggerstop()
{
	if [ "$IAM" != "root" ]
	then
		die "[!] Must be root"
	fi
	if [ "$PROXY" == 1 ] 
	then
		echo "[*] OpenFPC Proxy mode - Not touching daemonlogger" 
		return
	fi

	if [ -f $PID_PATH/$PID_FILE ] 
	then
		DPID=$(cat $PID_PATH/$PID_FILE) || die "[!] Cant read PID file $PID_PATH/$PID_FILE"
	else 
		die "[!] Wont stop. I don't think daemonlogger is running! No PID file $PID_PATH/$PID_FILE found"
	fi 

	kill $DPID 
	# Daemonlogger doesn't rm it's pid file. Need to look into this further, but as a quick 
	# fix lets rm it if it exists.

	[ -d $DPID ] && rm $DPID
	echo "[*] Traffic buffer (Daemonlogger) $DPID stopped"
}

function status()
{
	if ls $BUFFER_PATH/$FILENAME* > /dev/null 2>&1
	then
		FIRSTBUFFER=$(ls -tr $BUFFER_PATH/$FILENAME*|head -n 1)
		FIRSTPACKET=$(tcpdump -n -r $FIRSTBUFFER -c 1 -tttt 2>/dev/null |awk '{print $1 " " $2}')
		NOW=$(date +%Y-%m-%d\ %H:%M:%S)
		LASTBUFFER=$(ls -t $BUFFER_PATH/$FILENAME*|head -n 1)
		EPOC_FIRST=$(date -d "$FIRSTPACKET" +%s)
		EPOC_LAST=$(date -d "$NOW" +%s)
		let EPOC_DELTA=($EPOC_LAST-$EPOC_FIRST)/60/60
		SIZE=$(du $BUFFER_PATH -h | awk '{print $1}')
		USED=$(df $BUFFER_PATH -h |grep ^/ |awk '{print $5}')
		if [ -f $PID_PATH/$PID_FILE ]
		then
			DPID=$(cat $PID_PATH/$PID_FILE)
			if ps $DPID  > /dev/null
			then
				echo "[*] Traffic buffer (Daemonlogger) running with pid $DPID "
			fi
		else
				echo "[!] Traffic buffer (Daemonlogger) not running"
		fi

		echo -e " -  Time now                $NOW"
		echo -e " -  Oldest packet           $FIRSTPACKET"
		echo -e " -  Oldest File             $FIRSTBUFFER"
		echo -e " -  Using File              $LASTBUFFER"
		echo -e " -  Time Window             ~ $EPOC_DELTA hours"
		echo -e " -  Disk space used         $SIZE"
		echo -e " -  Partition utilization   $USED"
	else
		echo "[!] No current buffers found in $BUFFER_PATH - Have you started it yet?"
	fi
	
	if [ -f $OFPC_Q_PID ] 
	then
		echo -e "[-] Found OpenFPC Queued PID file $OFPC_Q_PID"
		QPID=$(cat $OFPC_Q_PID)
		if ps $QPID > /dev/null 2>&1
		then
			echo -e "[*] OpenFPC Queue Daemon running as Pid: $QPID"
		else
			echo -s "    Stale PID! $QPID Queued Not running"
		fi
	
	else 
		echo -e "[!] OpenFPC Queue Daemon not running!"
	fi	


	if [ -f $CXPIDFILE ] 
	then
		CXPID=$(cat $CXPIDFILE)
		if ps $CXPID > /dev/null
		then
			echo -e  "[*] cxtracker running as Pid: $CXPID"
		else
			echo -e "[!] cxtracker not running"
		fi
	fi
	if [ $ENABLE_SESSION == 1 ]
	then
		SESSION_LAG=$(ls -l $SESSION_DIR |grep -v failed | grep -v total | wc -l)
		echo -e " -  Session tempdir         $SESSION_DIR" 
		echo -e " -  Session lag             $SESSION_LAG"
	fi

}


case $1 in 
	start)
		daemonloggerstart
		cxtrackerstart
		openfpcqstart
	;;
	stop)
		cxtrackerstop
		daemonloggerstop
		openfpcqstop
	;;
	clean)
		clean	
	;;
	dlstart)
		daemonloggerstart
	;;
	dlstop)
		daemonloggerstop
	;;
	cxstart)
		cxtrackerstart
	;;
	cxstop)
		cxtrackerstop
	;;	
	qstop)
		openfpcqstop	
	;;	
	qstart)
		openfpcqstart
	;;	
	test)
		cxtrackerstop
	;;
	restart)
		cxtrackerstop
		daemonloggerstop
		openfpcqstop
		sleep 2
		daemonloggerstart
		cxtrackerstart
		openfpcqstart	
	;;
	status)
		status
	;;
	*)


echo -e "

    Usage 
    openpfc <action> <configfile>

    Note: If config file is not specified it will search some default locations

	-------------------------
	openfpc start      - Start all OpenFPC services
	openfpc stop       - Stop all OpenFPC services

	openfpc status     - Show OpenFPC status
	openfpc clean      - Delete old buffers

	openfpc cxstart    - Start cxtracker only
	openfpc cxstop     - Stop cxtracker only
	openfpc dlstart    - Daemonlogger start
	openfpc dlstop     - Daemonlogger stop
	openfpc qstop      - OpenFPC Queued stop
	openfpc qstart     - OpenFPC Queued start
"	
		
	;;
esac
