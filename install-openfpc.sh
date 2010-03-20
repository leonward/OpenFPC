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

TARGET_DIR="/opt/openfpc"
INSTALL_FILES="extract-pcap.pl openfpc openfpc.conf"
PERL_MODULES=""
INIT_SCRIPTS="openfpc"
INIT_DIR="/etc/init.d/" 
REQUIRED_BINS="tcpdump date mergecap perl tshark"

DISTRO="AUTO"		# Try to work out what distro we are installing on
# DISTRO="RH"		# force to RedHat
# DISTRO="Debian" 	# Force to Debian / Ubuntu



IAM=$(whoami)
DATE=$(date)
PATH=$PATH:/usr/sbin

function die()
{
        echo $1
        exit 1
}


function doinstall()
{
	echo Running Install.....

	if [ "$IAM" != "root" ]
	then
	       	die "[!] Must be root to run this script"
	fi

	for i in $REQUIRED_BINS
	do
		echo -e " Checking for $i "
		which $i > /dev/null || die "Unable to fined $i installed on this system. Please install it and try again"
	done


	[ -d $INIT_DIR ] || die "Cannot find init.d directory $INIT_DIR. Something bad must have happened."

        if [ -d $TARGET_DIR ] 
	then
                die "Cannot install - Directory Exists. Do you need to uninstall"
        else
                mkdir $TARGET_DIR
        fi
    
        for file in $INSTALL_FILES
        do
		echo -e " Installing $file"
                cp $file $TARGET_DIR || echo Unable to copy $file to $TARGET_DIR
        done

	for file in $PERL_MODULES
	do
		echo -e " Installing PERL module $file"
		[ -d $PERL_LIB_DIR ] || mkdir --parent $PERL_LIB_DIR
		ln -s $TARGET_DIR/$file $PERL_LIB_DIR/$file
	done

        for file in $INIT_SCRIPTS
        do
		echo -e " Installing $INIT_DIR/$file"
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
	ln -s $TARGET_DIR/extract-pcap.pl /usr/local/bin

}


function remove()
{
	echo -e "* Stopping Services..."

	for file in $INIT_SCRIPTS
	do
		echo -e " $file"
		$INIT_DIR/$file stop > /dev/null 2>&1 || echo -e " Unable to stop $file"
	done
	
	echo -e "* Removing files..."

	if [ "$IAM" != "root" ]
	then
	       	die "[!] Must be root to run this script"
	fi

	for file in $INSTALL_FILES
	do
		echo -e " - $TARGET_DIR/$file"
		if [ -f $TARGET_DIR/$file ] 
		then
			rm $TARGET_DIR/$file || echo unable to delete $file
		else
			echo -e "   * Not found"	
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
			rm $INIT_DIR/$file || echo unable to delete $file
		else
			echo -e " - $INIT_DIR/$file"
			echo -e "   * Not found"	
		fi
	done
	
	if [ -d $TARGET_DIR ] 
	then
		rm -r $TARGET_DIR  || echo unable to delete $TARGET_DIR
		echo Removed $TARGET_DIR
	fi


        if [ "$DISTRO" == "DEBIAN" ]
        then
                echo "Debain Install"

                for file in $INIT_SCRIPTS
                do
			echo -e " - Removing rc.d links for $file"
			update-rc.d $file remove
                done

        elif [ "$DISTRO" == "REDHAT" ]
        then
                echo "RedHat uninstall"
		rm /etc/rc3.d/S99trafficbuffer || echo "init script not found"
		rm /etc/rc0.d/K99trafficbuffer || echo "init script not found"
		rm /etc/rc5.d/S99trafficbuffer || echo "init script not found"
		rm /etc/rc6.d/K99trafficbuffer || echo "init script not found"
        fi

	rm /usr/local/bin/extract-pcap.pl
}

function installstatus()
{
	echo -e " Status"
	if [ -d $TARGET_DIR ] 
	then
		echo -e " - Target install dir $TARGET_DIR Exists"	
	else
		echo -e " - Target install dir $TARGET_DIR does not exist"

	fi
	
	for file in $INSTALL_FILES
	do
		if [ -f $TARGET_DIR/$file ] 
		then
			echo -e " - $TARGET_DIR/$file Exists"
		else
			echo -e " - $TARGET_DIR/$file  does not exist"
		fi

	done
	
	for file in $INIT_SCRIPTS
	do
	
		if [ -f $TARGET_DIR/$file ]
		then
			echo -e " = $TARGET_DIR/$file Exists"
		else
			echo -e " - $TARGET_DIR/$file does not exist"
		fi	
	done


}

if  [ "$DISTRO" == "AUTO" ]
then
	[ -f /etc/debian_version ]  && DISTRO="DEBIAN"
	[ -f /etc/redhat-release ] && DISTRO="REDHAT"

	if [ "$DISTRO" == "AUTO" ] 
	then
		die "Unable to detect distro. Set manually"
	fi

	echo "* Detected distribution as $DISTRO"
fi


case $1 in  
        install)
                doinstall
        ;;
        remove)
                remove
        ;;
        status)
                installstatus
        ;;
     *)
		echo -e "OpenFPC installer - Usage"
		echo -e "Leon Ward"
		echo -e " --------------"
                echo -e " insatall		Install the system"
                echo -e " remove		Uninstall the system"
                echo -e " status	 	Check install status"
		echo
        ;;
esac
