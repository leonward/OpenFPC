#!/bin/bash

#########################################################################################
# Copyright (C) 2010 - 2014 Leon Ward
# install-openfpc.sh - Part of the OpenFPC - (Full Packet Capture) project
#
# Contact: leon@openfpc.org
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

# This installer is for users that cannot or will not use the .debs for installation.
# It's goal is to take a system from being OpenFPC-less to one that has OpenFPC operating in a semi-standard setup.
# By semi-standard I refer to similar to how the .deb install leaves the system.
# It should be noted that the .debs have not been updated for 0.6 - 11/06/2011

openfpcver="0.9"
PROG_DIR="/usr/bin"
CONF_DIR="/etc/openfpc"
CONF_FILES="etc/openfpc-default.conf etc/openfpc-example-proxy.conf etc/routes.ofpc"
PROG_FILES="openfpc-client openfpc-queued openfpc-cx2db openfpc openfpc-dbmaint openfpc-password"
APIDIR="/opt/openfpc-restapi"

PERL_MODULES="Parse.pm Request.pm CXDB.pm Common.pm Config.pm"
INIT_SCRIPTS="openfpc-daemonlogger openfpc-cx2db openfpc-cxtracker openfpc-queued openfpc-restapi"
INIT_DIR="/etc/init.d/"
REQUIRED_BINS="tcpdump date mergecap perl tshark test"
LOCAL_CONFIG="/etc/openfpc/openfpc.conf"
PERL_LIB_DIR="/usr/share/perl5"
OFPC_LIB_DIR="$PERL_LIB_DIR/OFPC"
CXINSTALLED=0

DEPSOK=0			# Track if known deps are met
DISTRO="AUTO"		# Try to work out what distro we are installing on
# DISTRO="REDHAT"	# Force detection of distribution to RedHat
# DISTRO="Debian" 	# Force to detection of distribution to Debian / Ubuntu

IAM=$(whoami)
DATE=$(date)
PATH=$PATH:/usr/sbin
ACTION=$1
GUI=$2

function die()
{
        echo "$1"
        exit 1
}

function chkroot()
{
	if [ "$IAM" != "root" ]
	then
	       	die "[!] ERROR: Must be root to run this script"
	fi
}

function mkuser(){
	PASSFILE="/etc/openfpc/openfpc.passwd"
	echo "=============================================="
	echo "[*] EASY INSTALL"
	echo " -  Step 1: Creating a user to access OpenFPC."
	echo "    This user will be able to extract data and interact with the queue-daemon. "
	echo "    OpenFPC user & password management is controlled by the application openfpc-passwd. "
	echo "    The default OpenFPC passwd file is $PASSFILE"


  if [ -f $PASSFILE ]
    then
      echo "[-] Found existing password file $PASSFILE, wont add new user"
    else
	   for i in 1 2 3
	    do
		      openfpc-password -f $PASSFILE -a add && break
		      echo [!] Problem creating user, will try again.
	    done
  fi
}

function mksession(){
	echo "=============================================="
	echo "[*] Step 2: Creating an OpenFPC Session DB"
	echo "    OpenFPC uses cxtracker to record session data. Session data is much quicker to search through than whole packet data stored in a database."
	echo "    All of the databases used in OpenFPC are controlled by an application called openfpc-dbmaint. "
	echo "    - Note that you will need to enter the credentials of a mysql user that has privileges to creted/drop databases (most likely root)"

	sudo openfpc-dbmaint -a create -t session -c /etc/openfpc/openfpc-default.conf
	if [ $CXINSTALLED == "1" ]
	then
    echo "[-] Cxtracker is installed."
	else
		echo "[!] ***************************************"
    echo "    WARNING: cxtracker does not appear to be installed on this system."
		echo "    OpenFPC can operate without session searching, but it's a pretty useful feature."
    echo "    You're missing out."
		echo "[!] ***************************************"
	fi
}

function endmessage(){
	echo -e "
--------------------------------------------------------------------------
[*] Installation Complete

 ************************
 **      IMPORTANT     **
 ************************
 OpenFPC should now be installed and ready for *configuration*.

 1) Go configure /etc/openfpc/openfpc-default.conf
 2) Add a user E.g.

    $ sudo openfpc-password -a add -u admin \
	-f /etc/openfpc/openfpc.passwd

 3) Make a database for connection:
    $ sudo openfpc-dbmaint -a create -t session -c /etc/openfpc/openfpc-default.conf
 4) Start OpenFPC
    $ sudo openfpc --action start
 5) Check status (authenticate with user/password set in step 2)
    $ openfpc-client -a status --server localhost --port 4242
 6) Go extract files and search for sessions!
    $ openfpc-client -a search -dpt 53 --last 600
    $ openfpc-client -a  fetch -dpt 53 --last 600
    $ openfpc-client --help
"

}

function easymessage(){
	echo "[*] Starting OpenFPC"
	sudo openfpc -a start
	sudo service openfpc-restapi start

	echo "==============================================
[*] Installation complete.
Now would be a good time to read of docs/usage.md.
Here are a couple of tips to get started.

  $ openfpc-client -a status --server localhost --port 4242
  $ openfpc-client -a  fetch -dpt 53 --last 600
  $ openfpc-client -a search -dpt 53 --last 600
  $ openfpc-client --help
"
}

function checkdeps()
{
	force=$1
	if [ "$force" == "1" ]
	then
		echo "[*] Won't stop on failed deps, forceinstall set"
	fi

	missdeps=""
	if [ "$DISTRO" == "DEBIAN" ]
	then
		DEPS="daemonlogger tcpdump tshark libdatetime-perl libprivileges-drop-perl libarchive-zip-perl libfilesys-df-perl mysql-server libdbi-perl libterm-readkey-perl libdate-simple-perl libdigest-sha-perl libjson-pp-perl libdatetime-perl libswitch-perl libdatetime-format-strptime-perl libdata-uuid-perl libdancer2-perl starman"

		# Check if some obvious dependencies are met
		for dep in $DEPS
		do
			echo -e "[-] Checking for $dep ..."
			if  dpkg --status $dep > /dev/null 2>&1
			then
				echo -e "    $dep Okay"
			else
				DEPSOK=1
				echo -e "    ERROR: Package $dep is not installed."
				missdeps="$missdeps $dep"
			fi
		done

	elif [ "$DISTRO" == "REDHAT" ]
	then
		DEPS="httpd perl-Archive-Zip perl-DateTime perl-Filesys-Df perl-DateTime-Format-DateParse perl-TermReadKey perl-Date-Simple tcpdump wireshark"
		echo -e "[-] Checking status on RedHat"

		# Check if some obvious dependencies are met
		for dep in $DEPS
		do
			echo -e "[-] Checking for $dep ..."
			if  rpm -q $dep > /dev/null 2>&1
			then
				echo -e "    $dep Okay
"			else
				DEPSOK=1
				echo -e "[!] ERROR: Package $dep is not installed."
				missdeps="$missdeps $dep"
			fi
		done
	else
		echo -e "Package checking only supported on Debian/Redhat OSs"
		echo "Use --force to skip package checks, and fix any problems by hand"
	fi


	if [ "$DEPSOK" != 0 ]
	then
		echo -e "[-] --------------------------------"
		echo -e "Problem with above dependencies, please install them before continuing"
		if [ "$DISTRO" == "DEBIAN" ]
		then
			echo -e "As you're running a distro based on Debian..."
			echo -e "Hint: sudo apt-get install the stuff that's missing above\n"
			echo -e " apt-get install $missdeps\n"
		else
			echo -e "As you're running a distro based on RedHat..."
			echo -e "Hine 1) Enable rpmforge"
			echo -e "Hint 2) sudo yum install httpd perl-Archive-Zip"
			echo -e "Hint 3) sudo yum --enablerepo=rpmforge install perl-DateTime perl-Filesys-Df "
		fi

		if [ $force == "1" ]
		then
			echo "[!] Force install selected, won't stop here..."
		else
			exit 1
		fi
	fi

	# Extra warning for cxtracker as it's not included in either of the distros we work with
	#
	if which cxtracker
	then
		echo "[*] Found cxtracker in your \$PATH (good)"
		CXINSTALLED=1
	else
		echo -e "
###########################################################
# WARNING: No cxtracker found in path!
###########################################################
# Don't Panic!
# This may be Okay if you expect it not to be found.
# cxtracker likely isn't included as part of your Operating System's
# package manager. Go grab it from www.openfpc.org/downloads.
# Without cxtracker OpenFPC will function, but you loose
# the ability to search flow/connection data.
#
# All full packet capture and extraction capabilities will
# still function without cxtracker.
# -Leon
###########################################################
"
	fi
}

function purge()
{
  echo "[*] Removing all content in $CONF_DIR"
  if [ -d $CONF_DIR ]
    then
    rm -rf $CONF_DIR
  else
    echo "[!] Unable to find conf_dir $CONF_DIR, won't unlink"
  fi

}

function doinstall()
{

	chkroot
	# Setup install for distro type
	if [ "$DISTRO" == "DEBIAN" ]
	then
    	OFPC_LIB_DIR="$PERL_LIB_DIR/OFPC"
	elif [ "$DISTRO" == "REDHAT" ]
	then
		PERL_LIB_DIR="/usr/local/share/perl5"
    	OFPC_LIB_DIR="$PERL_LIB_DIR/OFPC"
	fi

	# Unbuntu apparmor prevents tcpdump from reading and writing to files outside of $HOME.
	# this breaks openfpc.
	echo "[*] Disabling apparmor profile for tcpdump"
	sudo ln -s /etc/apparmor.d/usr.sbin.tcpdump /etc/apparmor.d/disable/
	sudo /etc/init.d/apparmor restart

	##################################
	# Check for Dirs
	# Check for, and create if required a /etc/openfpc dir
    if [ -d $CONF_DIR ]
	then
		echo -e " -  Found existing config dir $CONF_DIR "
	else
		mkdir -p $CONF_DIR || die "[!] Unable to mkdir $CONF_DIR"
	fi

	# Check the perl_lib_dir is in the Perl path
	if  perl -V | grep "$PERL_LIB_DIR" > /dev/null
	then
		echo " -  Installing modules to $PERL_LIB_DIR"
	else
		die "[!] Perl include path problem. Cannot find $PERL_LIB_DIR in Perl's @INC (perl -V to check)"
	fi

	# Check four our include dir
    if [ -d $OFPC_LIB_DIR ]
	then
		echo -e " -  $OFPC_LIB_DIR exists"
	else
		mkdir --parent $OFPC_LIB_DIR || die "[!] Unable to mkdir $OFPC_LIB_DIR"
	fi

	# Check for init dir
	[ -d $INIT_DIR ] || die "[!] Cannot find init.d directory $INIT_DIR. Something bad must have happened."

	# Splitting GUI apart from main program
	#if [ -d $WWW_DIR ]
	#then
	#	echo -e " *  Found $WWW_DIR"
	#else
	#	mkdir --parent $WWW_DIR || die "[!] Unable to mkdir $WWW_DIR"
	#fi


	####################################
	# Install files

	######## Modules ###########

	for file in $PERL_MODULES
	do
		echo -e " -  Installing PERL module $file"
		cp OFPC/$file $OFPC_LIB_DIR/$file
	done

	###### Programs ######

	for file in $PROG_FILES
	do
		echo -e " -  Installing OpenFPC Application: $file"
		cp $file $PROG_DIR
	done

	###### Config files ######

	for file in $CONF_FILES
	do
		basefile=$(basename $file)
		if [ -f $CONF_DIR/$basefile ]
		then
			echo -e " -  Skipping Config file $CONF_DIR/$basefile already exists!"
		else
			echo -e " -  Installing OpenFPC conf: $file"
			cp $file $CONF_DIR
		fi
	done

	###### WWW files #####
	# I'm separating the GUI out from the main program.
	#
	# for file in $GUI_FILES
	# do
	#	echo -e " -  Installing $file"
	#	cp -r www/$file $WWW_DIR/$file
	# done
	echo -----------------


	echo -----------------
	###### init #######

    for file in $INIT_SCRIPTS
    do
		echo -e " -  Installing $INIT_DIR/$file"
		cp etc/init.d/$file $INIT_DIR/$file
    done


	##### Distribution specific post installation stuff

	if [ "$DISTRO" == "DEBIAN" ]
	then

		#################################
		# Init scripts
		echo "[*] Updating init config with update-rc.d"

		for file in $INIT_SCRIPTS
		do
		 	update-rc.d $file defaults

			if ! getent passwd openfpc >/dev/null
			then
				echo -e "[*] Adding user openfpc"
  				adduser --quiet --system --group --no-create-home --shell /usr/sbin/nologin openfpc
			fi
		done

	elif [ "$DISTRO" == "REDHAT" ]
	then
		echo "[*] Performing a RedHat Install"
		echo "[-] RedHat install is un-tested by me, I don't use use: Your millage may vary."
		PERL_LIB_DIR="/usr/local/share/perl5"
	fi


}

function remove()
{
	echo -e "[*] Stopping Services..."
	chkroot
	for file in $INIT_SCRIPTS
	do
		if [ -f $INIT_DIR/$file ]
		then
			echo -e "Stopping $file"
			$INIT_DIR/$file stop || echo -e " -  $file didn't stop, removing anyway"
		else
			echo -e " -  $INIT_DIR/$file doesn't exist - Won't try to stop"
		fi
	done

	echo -e "[*] Removing openfpc-programs ..."

	for file in $PROG_FILES
	do
		if [ -f $PROG_DIR/$file ]
		then
			echo -e "    Removed   $PROG_DIR/$file"
			rm $PROG_DIR/$file || echo -e "unable to delete $PROG_DIR/$file"
		else
			echo -e "    Cannot Find $PROG_DIR/$file"
		fi
	done

	echo -e "[*] Removing PERL modules"
	for file in $PERL_MODULES
	do
		if [ -f $OFPC_LIB_DIR/$file ]
		then
			rm $OFPC_LIB_DIR/$file  || echo -e "[!] Unable to delete $file"
		else
			echo -e "    Cannot Find $OFPC_LIB_DIR/$file"
		fi
	done

	echo -e "[*] Removing WWW files"
	for file in $WWW_FILES
	do
		if [ -f $WWW_DIR/$file ]
		then
			rm $WWW_DIR/$file  || echo -e "[!] Unable to delete $WWW_DIR/$file"
		else
			echo -e "    Cannot Find $WWW_DIR/$file"
		fi
	done


	echo -e "[*] Updating init sciprts"
    if [ "$DISTRO" == "DEBIAN" ]
    then
    	for file in $INIT_SCRIPTS
        do
			update-rc.d -f $file remove
                done

		if getent passwd openfpc >/dev/null
		then
			echo "[*] Removing user openfpc"
			deluser openfpc  > /dev/null
		fi

        elif [ "$DISTRO" == "REDHAT" ]
	then
		echo NOT DONE
	fi
	echo -e "[-] -----------------------------------------------"

        for file in $INIT_SCRIPTS
        do
		if [ -f $INIT_DIR/$file ]
		then
			echo -e " -  Removing $INIT_DIR/$file"
			rm $INIT_DIR/$file
		fi
        done

	echo -e "[*] Removal process complete"
}

function installstatus()
{
	SUCCESS=1

	echo -e "* Status"
	if [ -d $PROG_DIR ]
	then
		echo -e "  Yes Target install dir $PROG_DIR Exists"
	else
		echo -e "  No  Target install dir $PROG_DIR does not exist"
		SUCCESS=0

	fi

	echo "- Init scripts"
	for file in $INIT_SCRIPTS
	do
		if [ -f $INIT_DIR/$file ]
		then
			echo -e "  Yes $INIT_DIR/$file Exists"
		else
			echo -e "  No  $INIT_DIR/$file does not exist"
			SUCCESS=0
		fi
	done

	echo -e "- Perl modules"
	for file in $PERL_MODULES
	do
		if [ -f $OFPC_LIB_DIR/$file ]
		then
			echo -e "  Yes $OFPC_LIB_DIR/$file Exists"
		else
			echo -e "  No  $OFPC_LIB_DIR/$file does not exist"
			SUCCESS=0
		fi
	done
	echo -e "- Program Files"
	for file in $PROG_FILES
	do
		if [ -f $PROG_DIR/$file ]
		then
			echo -e "  Yes $PROG_DIR/$file Exists"
		else
			echo -e "  No  $PROG_DIR/$file does not exist"
			SUCCESS=0
		fi
	done

	echo -e "- Dependencies "
	for file in $REQUIRED_BINS
	do
		which $file > /dev/null
		if [ $? -ne 0 ]
		then
			echo -e "  No  Application $file is not installed"
			SUCCESS=0
		else
			echo -e "  Yes Application $file is installed"
		fi
	done

	echo
	if [ $SUCCESS == 1 ]
	then

		echo -e "  Installation looks Okay"
	else
		echo -e "  OpenFPC is not installed correctly. Check the above for missing things."
	fi
	echo
}

function genkeys()
{
	echo -e "[*] Generating SSL keys for OpenFPC RestAPI"
	KEYFILE=ofpcapi.key.pem
	CERTFILE=ofpcapi.cert.pem
	COMBINED=ofpcapi.combined.pem

	if [ -f $CONF_DIR/$COMBINED ]
	then
		echo -e " -  Found existing key and cert: $COMBINED"
	else
		echo -e " -  Generating temporary key $KEYFILE."
		echo -e " -  Please remember to change this to something real. Should not be used in production."
		pushd $CONF_DIR
		openssl genrsa -out $KEYFILE 2048
		echo -e " - Generating Certificate $CERTFILE"
		openssl req \
			-new -x509 \
			-key $CONF_DIR/$KEYFILE \
			-out $CONF_DIR/$CERTFILE \
			-days 1000 \
			-subj "/C=NA/ST=NA/L=None/O=None/CN=$HOSTNAME"
		cat $CONF_DIR/$KEYFILE $CONF_DIR/$CERTFILE > $CONF_DIR/$COMBINED
		popd
	fi
	echo -e "[*] Done generating keys"

}

enrestapi()
{
	echo -e "[*] Installing files for OpenFPC RestAPI"
	# Deploy the OpenFPC rest api into /opt
	###### API files #######

	if [ -d $APIDIR ]
	then
		echo -e " -  Found existing OpenFPC API dir $APIDIR"
	else
		mkdir -p $APIDIR || die "[!] Unable to mkdir $APIDIR"
	fi

	###### API files #######
	cp -r openfpc-restapi/* $APIDIR
}

disrestapi()
{
	echo -e "[*] Stopping OpenFPC RestAPI"
  service openfpc-restapi stop
	echo -e "[*] Removing files for OpenFPC RestAPI"

	echo -e "[*] Removing API files"
	APIPARENT=$(dirname $APIDIR)
	if [ -d $APIDIR ]
	then
		rm $APIPARENT/openfpc-restapi -rf  || echo -e "[!] Unable to delete $APIPARENT/openfpc-restapi"
	else
		echo -e "    Cannot Find openfpc-restapi directory in path $APIPARENT. Looking for $APIPARENT/openfpc-restapi"
	fi
}

echo -e "
 *************************************************************************
 *  OpenFPC installer - Leon Ward (leon@openfpc.org) v$openfpcver
 *  A set if scripts to help manage and find data in a large network traffic
 *  archive.

 *  http://www.openfpc.org
"



if  [ "$DISTRO" == "AUTO" ]
then
	[ -f /etc/debian_version ]  && DISTRO="DEBIAN"
	[ -f /etc/redhat-release ] && DISTRO="REDHAT"

	if [ "$DISTRO" == "AUTO" ]
	then
		die "[*] Unable to detect distribution. Please set it manually in the install script. Variable: DISTRO=<>"
	fi

	echo -e "[*] Detected distribution as $DISTRO-like \n"
fi

case $1 in
    files)
		checkdeps 0
        doinstall
        genkeys
        enrestapi
        endmessage
    ;;
    forceinstall)
		echo [*] Installing OpenFPC
		checkdeps 1
		doinstall
		enrestapi
		genkeys
		mkuser
		mksession
		easymessage
    ;;
    remove)
    	remove
		  disrestapi
    ;;
    purge)
      remove
      purge
      disrestapi
    ;;
    status)
    	installstatus
    ;;
	reinstall)
		echo [*] Running reinstall remove
		remove
		disrestapi
		echo [*] Running reinstall install
		checkdeps 0
		doinstall
		enrestapi
		genkeys
		endmessage
	;;
	install)
		echo [*] Installing OpenFPC
		checkdeps 0
		doinstall
		enrestapi
		genkeys
		mkuser
		mksession
		easymessage
	;;
     *)
        echo -e "
[*] openfpc-install.sh usage:
    $ openfpc-install <action> <gui>

    Where <action> is one of the below:
    install       - Install and auto-configure. Good for first time users
    files         - Only install OpenFPC programs, don't auto-configure
    forceinstall  - Install OpenFPC without checking for dependencies
    remove        - Uninstall OpenFPC
    purge         - Uninstall OpenFPC and purge all config from /etc/openfpc
    status        - Check installation status
    reinstall     - Re-install OpenFPC (remove then install in one command)
                    Note that dependencies will not be checked in reinstall

[*] Examples:
    Easy Install: Get OpenFPC running for the 1st time, many defaults are
    selected for you. Just answer a couple of questions.
    $ sudo ./openfpc-install install

    Remove OpenFPC:
    $ sudo ./openfpc-install remove
"
    ;;
esac
