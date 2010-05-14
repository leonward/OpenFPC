#!/bin/bash -e

#########################################################################################
# Copyright (C) 2009 Leon Ward 
# install-openfpc.sh - Part of the OpenFPC - (Full Packet Capture) project
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
openfpcver="0.1"
TARGET_DIR="/opt/openfpc"
INSTALL_FILES="ofpc-extract.pl openfpc openfpc.conf ofpcParse.pm"
PERL_MODULES="ofpcParse.pm"
INIT_SCRIPTS="openfpc"
INIT_DIR="/etc/init.d/" 
REQUIRED_BINS="tcpdump date mergecap perl tshark"
LOCAL_CONFIG="/etc/openfpc/openfpc.conf"

DISTRO="AUTO"		# Try to work out what distro we are installing on
# DISTRO="RH"		# force to RedHat
# DISTRO="Debian" 	# Force to Debian / Ubuntu



IAM=$(whoami)
DATE=$(date)
PATH=$PATH:/usr/sbin

function die()
{
        echo "$1"
        exit 1
}


function doinstall()
{

	if [ "$IAM" != "root" ]
	then
	       	die "[!] Must be root to run this script"
	fi


	[ -d $INIT_DIR ] || die "Cannot find init.d directory $INIT_DIR. Something bad must have happened."

        if [ -d $TARGET_DIR ] 
	then
                die "Can't Install in $TARGET_DIR - Directory Exists."
        else
                mkdir $TARGET_DIR
        fi
    
        for file in $INSTALL_FILES
        do
		echo -e "- Installing $file"
                cp $file $TARGET_DIR || echo Unable to copy $file to $TARGET_DIR
        done

	for file in $PERL_MODULES
	do
		echo -e "- Installing PERL module $file"
		[ -d $PERL_LIB_DIR ] || mkdir --parent $PERL_LIB_DIR
		ln -s $TARGET_DIR/$file $PERL_LIB_DIR/$file
	done

        for file in $INIT_SCRIPTS
        do
		echo -e "- Installing $INIT_DIR/$file"
                ln -s $TARGET_DIR/$file /$INIT_DIR/$file  || echo Unable to symlink $file into $INIT_DIR/$file
        done

	if [ "$DISTRO" == "DEBIAN" ]
	then
		echo "Debain Install"

		for file in $INIT_SCRIPTS
		do
			echo -e " Updating rc.d with $file"
		 	update-rc.d $file defaults
		done
	elif [ "$DISTRO" == "REDHAT" ]
	then
		echo "RedHat Install"
		ln -s /etc/init.d/trafficbuffer /etc/rc3.d/S99trafficbuffer || echo "File exists"
		ln -s /etc/init.d/trafficbuffer /etc/rc5.d/S99trafficbuffer || echo "File exists"
		ln -s /etc/init.d/trafficbuffer /etc/rc6.d/K99trafficbuffer || echo "File exists"
		ln -s /etc/init.d/trafficbuffer /etc/rc0.d/K99trafficbuffer || echo "File exists"
	fi

	echo -e "Creating symlink to usr/local/bin"
	ln -s $TARGET_DIR/ofpc-extract.pl /usr/local/bin


	echo -e "--------Installation Complete--------"
}


function remove()
{
	echo -e "* Stopping Services..."

	for file in $INIT_SCRIPTS
	do
		if [ -f $INIT_DIR/$file ] 
		then 
			echo -e "Stopping $file"
			$INIT_DIR/$file stop || echo "- $file didn't stop, removing anyway"
		else
			echo -e "  $INIT_DIR/$file doesn't exist - Won't try to stop"
		fi
	done
	
	echo -e "* Removing files..."

	if [ "$IAM" != "root" ]
	then
	       	die "[!] Must be root to run this script"
	fi

	for file in $INSTALL_FILES
	do
		if [ -f $TARGET_DIR/$file ] 
		then
			echo -e "  Removed   $TARGET_DIR/$file"
			rm $TARGET_DIR/$file || echo unable to delete $file
		else
			echo -e "  Not Found $TARGET_DIR/$file"	
		fi
	done

	echo -e "* Removing perl modules"
	for file in $PERL_MODULES
	do
		if [ -L $PERL_LIB_DIR/$file ]
		then	
			rm $PERL_LIB_DIR/$file  || echo unable to delete $file
		else
			echo -e " - *Not found"
		fi
	done

	echo -e "* Removing Symlinks..."
	for file in $INIT_SCRIPTS
	do
		if [ -L $INIT_DIR/$file ] 
		then
			if rm $INIT_DIR/$file 
			then
				echo -e " Removed   $INIT_DIR/$file "
			else
				echo -e " rm failed $INIT_DIR/$file"
			fi
		else
			echo -e "  Can't find $INIT_DIR/$file - Won't remove"
		fi
	done
	
	if [ -d $TARGET_DIR ] 
	then
		rm -r $TARGET_DIR  || echo unable to delete $TARGET_DIR
		echo Removed $TARGET_DIR
	fi


        if [ "$DISTRO" == "DEBIAN" ]
        then
                for file in $INIT_SCRIPTS
                do
			update-rc.d $file remove
                done

        elif [ "$DISTRO" == "REDHAT" ]
        then
		rm /etc/rc3.d/S99trafficbuffer || echo "init script not found"
		rm /etc/rc0.d/K99trafficbuffer || echo "init script not found"
		rm /etc/rc5.d/S99trafficbuffer || echo "init script not found"
		rm /etc/rc6.d/K99trafficbuffer || echo "init script not found"
        fi
	if [ -h /usr/local/bin/ofpc-extract.pl ]
	then
		rm /usr/local/bin/ofpc-extract.pl || echo "/usr/local/bin/ofpc-extract.pl not found"
	fi
}

function installstatus()
{
	echo -e "* Status"
	if [ -d $TARGET_DIR ] 
	then
		echo -e " Yes Target install dir $TARGET_DIR Exists"	
	else
		echo -e " No  Target install dir $TARGET_DIR does not exist"

	fi
	
	for file in $INSTALL_FILES
	do
		if [ -f $TARGET_DIR/$file ] 
		then
			echo -e " Yes $TARGET_DIR/$file Exists"
		else
			echo -e " No  $TARGET_DIR/$file  does not exist"
		fi

	done
	
	for file in $INIT_SCRIPTS
	do
	
		if [ -f $TARGET_DIR/$file ]
		then
			echo -e " Yes $TARGET_DIR/$file Exists"
		else
			echo -e " No  $TARGET_DIR/$file does not exist"
		fi	
	done
}

echo -e "
* OpenFPC installer - leon@rm-rf.co.uk v$openfpcver
  A set if scripts to help manage and find data in a large network traffic
  archive. - http://code.google.com/p/openfpc/ 
"
	


if  [ "$DISTRO" == "AUTO" ]
then
	[ -f /etc/debian_version ]  && DISTRO="DEBIAN"
	[ -f /etc/redhat-release ] && DISTRO="REDHAT"

	if [ "$DISTRO" == "AUTO" ] 
	then
		die "Unable to detect distro. Set manually"
	fi

	echo -e "* Detected distribution as $DISTRO\n"
fi

function checkdeps() {

	source $TARGET_DIR/openfpc.conf
	echo -e "* Checking for dependancies"
	[ -f $MERGECAP ] || echo "WARNING - Can't find mergecap in $MERGECAP - Make sure that it's installed and correctly configured in openfpc.conf. \nHint -> Install the wireshark / tshak packages" 
	[ -f $TCPDUMP ] || echo "WARNING - Cant find tcpdump in location $TCPDUMP - Make sure it is installed and correctly configured in openfpc.conf. \nHint -> Install the tcpdump package on your system"

}

case $1 in  
        install)
                doinstall
		checkdeps
        ;;
        remove)
                remove
        ;;
        status)
                installstatus
        ;;
	reinstall)
		echo Running REINSTALL
		remove
		echo And installing...
		doinstall
	;;
	check)
		echo Checking for dependencies
		checkdeps
	;;
     *)
                echo -e " install   - Install the system"
                echo -e " remove     - Remove the system"
                echo -e " status     - Check install status"
                echo -e " reinstall  - Re-install system"
		echo -e "\nUsage: ./install-openfpc <command>"
        ;;
esac
