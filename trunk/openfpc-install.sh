#!/bin/bash 

#########################################################################################
# Copyright (C) 2010 Leon Ward 
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
# By semi-standard i refer to similar to how the .deb install leaves the system.
# It should be noted that the .debs have not been updated for 0.6 - 11/06/2011

openfpcver="0.7"
PROG_DIR="/usr/bin"
CONF_DIR="/etc/openfpc"
CONF_FILES="etc/openfpc-default.conf etc/openfpc-example-proxy.conf etc/routes.ofpc"
PROG_FILES="openfpc-client openfpc-queued openfpc-cx2db openfpc openfpc-dbmaint openfpc-password"
GUI_FILES="css images includes index.php javascript login.php useradd.php"
WWW_DIR="/usr/share/openfpc/www"
CGI_FILES="extract.cgi"
CGI_DIR="/usr/share/openfpc/cgi-bin"
PERL_MODULES="Parse.pm Request.pm CXDB.pm Common.pm Config.pm"
INIT_SCRIPTS="openfpc-daemonlogger openfpc-cx2db openfpc-cxtracker openfpc-queued"
INIT_DIR="/etc/init.d/" 
REQUIRED_BINS="tcpdump date mergecap perl tshark"
LOCAL_CONFIG="/etc/openfpc/openfpc.conf"
PERL_LIB_DIR="/usr/local/lib/site_perl"
OFPC_LIB_DIR="$PERL_LIB_DIR/OFPC"

DEPSOK=0		# Track if obvious deps are met
DISTRO="AUTO"		# Try to work out what distro we are installing on
# DISTRO="REDHAT"		# force to RedHat
# DISTRO="Debian" 	# Force to Debian / Ubuntu

IAM=$(whoami)
DATE=$(date)
PATH=$PATH:/usr/sbin

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

function checkdeps()
{
	if [ "$DISTRO" == "DEBIAN" ] 
	then
		DEPS="apache2 daemonlogger tcpdump tshark libarchive-zip-perl libfilesys-df-perl libapache2-mod-php5 mysql-server php5-mysql libdatetime-perl libdbi-perl libdate-simple-perl php5-mysql libterm-readkey-perl libdate-simple-perl " 

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
			fi
		done	

	elif [ "$DISTRO" == "REDHAT" ] 
	then
		DEPS="httpd perl-Archive-Zip perl-DateTime perl-Filesys-Df"
		echo -e "[-] Checking status on RedHat"

		# Check if some obvious dependencies are met	
		for dep in $DEPS
		do
			echo -e "[-] Checking for $dep ..."
			if  rpm -q $dep > /dev/null 2>&1
			then
				echo -e "    $dep Okay"
			else
				DEPSOK=1
				echo -e "[!] ERROR: Package $dep is not installed."
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
			echo -e "Hint: sudo apt-get install $DEPS\n"
		else 
			echo -e "As you're running a distro based on RedHat..."
			echo -e "Hine 1) Enable rpmforge"
			echo -e "Hint 2) sudo yum install httpd perl-Archive-Zip"
			echo -e "Hint 3) sudo yum --enablerepo=rpmforge install perl-DateTime perl-Filesys-Df "	
		fi

		exit 1
	fi

	# Extra warning for cxtracker as it's not included in either of the distros we work with
	# 
	if which cxtracker
	then
		echo "* Found cxtracker in your \$PATH (good)"
	else
		echo -e "
###########################################################
# WARNING: No cxtracker found in path!
###########################################################
# Don't Panic! 
# This may be Okay if you expect it not to be found.
# cxtracker likely isn't included as part of your distro's
# package manager. Go grab it from www.openfpc.org/downloads
# Without cxtracker OpenFPC will function, but you loose 
# the ability to search flow/connection data in the web UI.
# All PCAP capture and extraction capabilities will still function.
# -Leon
###########################################################
"
	fi 
}

function doinstall()
{

	chkroot
	# Setup install for distro type
	if [ "$DISTRO" == "DEBIAN" ]
	then
		PERL_LIB_DIR="/usr/local/lib/site_perl"
	elif [ "$DISTRO" == "REDHAT" ]
	then
		PERL_LIB_DIR="/usr/local/share/perl5"
	fi



	##################################
	# Check for Dirs

	# Check for, and create if required a /etc/openfpc dir
        if [ -d $CONF_DIR ] 
	then
		echo -e " -  Found existing config dir $CONF_DIR "
	else
		mkdir $CONF_DIR || die "[!] Unable to mkdir $CONF_DIR"
	fi

	# Check the perl_lib_dir is in the perl path
	if  perl -V | grep "$PERL_LIB_DIR" > /dev/null
	then
		echo " -  Installing modules to $PERL_LIB_DIR"
	else
		die "[!] Perl include path problem. Cant find $PERL_LIB_DIR in Perl's @INC (perl -V to check)"
	fi	

	# Check four our inclide dir	
        if [ -d $OFPC_LIB_DIR ] 
	then
		echo -e " -  $OFPC_LIB_DIR exists"
	else
		mkdir --parent $OFPC_LIB_DIR || die "[!] Unable to mkdir $OFPC_LIB_DIR"
	fi

	# Check for init dir
	[ -d $INIT_DIR ] || die "[!] Cannot find init.d directory $INIT_DIR. Something bad must have happened."

	if [ -d $WWW_DIR ] 
	then
		echo -e " *  Found $WWW_DIR"
	else
		mkdir --parent $WWW_DIR || die "[!] Unable to mkdir $WWW_DIR"
	fi
	if [ -d $CGI_DIR ] 
	then
		echo -e " *  Found $CGI_DIR"
	else
		mkdir --parent $CGI_DIR || die "[!] Unable to mkdir $CGI_DIR"
	fi

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
		echo -e " -  Installing OpenFPC prog: $file"
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


	for file in $GUI_FILES
	do
		echo -e " -  Installing $file"
		cp -r www/$file $WWW_DIR/$file
	done

	###### CGI files #####

	for file in $CGI_FILES
	do
		echo -e " -  Installing $file"
		cp cgi-bin/$file $CGI_DIR/$file
	done


	###### init #######

        for file in $INIT_SCRIPTS
        do
		echo -e " -  Installing $INIT_DIR/$file"
		cp etc/init.d/$file $INIT_DIR/$file
        done


	##### Distro specific postinst stuff

	if [ "$DISTRO" == "DEBIAN" ]
	then
		#################################
		# Enable website

		if [ -d /etc/apache2/sites-available ]
		then
			echo -e "[*] Enabling and restarting Apache2"	
			# Add openfpc config in apache
			cp etc/openfpc.apache2.site /etc/apache2/sites-available/
			a2ensite openfpc.apache2.site
			service apache2 reload
		else
			echo -e "[!] Cant find apache conf dir. Won't enable web UI"
		fi
		echo "[*] Updating init config with update-rc.d"

		#################################
		# Init scripts

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
		echo "[*] Performing a RedHat init Install"
		echo "[-] RedHat install un-tested. YMMV"
		PERL_LIB_DIR="/usr/local/share/perl5"

		#################################
		# Enable website

		if [ -d /etc/httpd/conf.d ]
		then
			echo -e "[*] Enabling and restarting httpd"	
			# Add openfpc config in apache
			cp etc/openfpc.apache2.site /etc/httpd/conf.d
			/etc/init.d/httpd restart
		else
			echo -e "[!] Cant find apache conf dir. Won't enable web UI"
		fi

	fi

        # Disable basic auth now that we have GUI based acl
	#if [ -f /etc/openfpc/apache2.passwd ] 
	#then
	#	echo " -   Skipping basic auth passwd. File exists"
	#else
	#	echo -e "[-] -----------------------------------------------------"
	#	echo "OpenFPC has a web UI. For now we use Basic Auth to secure it"
	#	read -p "Username: " user
	#	htpasswd -c /etc/openfpc/apache2.passwd $user
	#fi

	echo -e "
**************************************************************************
[*] Installation Complete 

    OpenFPC should now be installed and ready for *configuration*.
   
    1) Go configure /etc/openfpc/openfpc-default.conf
       (Make sure you change the usernames and passwords!)
    2) Start OpenFPC
       $ sudo openfpc --action start
    3) If you want to use the OpenFPC GUI, you MUST create the GUI database
       - Install Mysql
       - Create the DB with the command...
         sudo ./openfpc-dbmaint create gui /etc/openfpc/openfpc-default.conf
    4) Decide if you want to enable session searching
       See -> http://www.openfpc.org/documentation/enabling-session-capture
"
}

function remove()
{
	echo -e "* Stopping Services..."
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

	echo -e "[*] Disabling OpenFPC GUI"
	if [ -f /etc/apache2/sites-available/openfpc.apache2.site ]
	then	
		a2dissite openfpc.apache2.site
		service apache2 reload
	fi
	[ -f /etc/apache2/sites-available/openfpc.apache2.site ] && rm /etc/apache2/sites-available/openfpc.apache2.site 


	echo -e "[*] Removing openfpc-progs ..."

	for file in $PROG_FILES
	do
		if [ -f $PROG_DIR/$file ] 
		then
			echo -e "    Removed   $PROG_DIR/$file"
			rm $PROG_DIR/$file || echo -e "unable to delete $PROG_DIR/$file"
		else
			echo -e "    Cant Find $PROG_DIR/$file"	
		fi
	done
	
	echo -e "[*] Removing PERL modules"
	for file in $PERL_MODULES
	do
		if [ -f $OFPC_LIB_DIR/$file ]
		then	
			rm $OFPC_LIB_DIR/$file  || echo -e "[!] Unable to delete $file"
		else
			echo -e "    Cant Find $OFPC_LIB_DIR/$file"
		fi
	done

	echo -e "[*] Removing WWW files"
	for file in $WWW_FILES
	do
		if [ -f $WWW_DIR/$file ]
		then	
			rm $WWW_DIR/$file  || echo -e "[!] Unable to delete $WWW_DIR/$file"
		else
			echo -e "    Cant Find $WWW_DIR/$file"
		fi
	done
	echo -e "[*] Removing CGI files"
	for file in $CGI_FILES
	do
		if [ -f $CGI_DIR/$file ]
		then	
			rm $CGI_DIR/$file  || echo -e "[!] Unable to delete $CGI_DIR/$file"
		else
			echo -e "    Cant Find $CGI_DIR/$file"
		fi
	done

	# Remove the password file if it has been created
	#[ -f $CONF_DIR/apache2.passwd ] && rm $CONF_DIR/apache2.passwd

	echo -e "[*] Removing openfpc wwwroot"
	if [ -d $WWW_DIR ] 
	then
		rm -r $WWW_DIR  || echo -e "[!] Unable to delete $WWW_DIR"
		echo -e " -  Removed $WWW_DIR"
	fi

	echo -e "[-] Updating init sciprts"
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


	echo -e "[-] ----------------------------------"
	if [ $SUCCESS == 1 ] 
	then
		echo -e "  Installation Okay"
	else
		echo -e "  OpenFPC is not installed correctly"
	fi
	echo -e "[-] --------------------------------"
}

echo -e "
**************************************************************************
 *  OpenFPC installer - Leon Ward (leon@openfpc.org) v$openfpcver
    A set if scripts to help manage and find data in a large network traffic
    archive. 

    - http://www.openfpc.org 
"
	


if  [ "$DISTRO" == "AUTO" ]
then
	[ -f /etc/debian_version ]  && DISTRO="DEBIAN"
	[ -f /etc/redhat-release ] && DISTRO="REDHAT"

	if [ "$DISTRO" == "AUTO" ] 
	then
		die "[*] Unable to detect distro. Set manually"
	fi

	echo -e "[*] Detected distribution as $DISTRO\n"
fi

case $1 in  
        install)
		checkdeps
                doinstall
        ;;
        forceinstall)
                doinstall
        ;;
        remove)
                remove
        ;;
        status)
                installstatus
        ;;
	reinstall)
		echo [*] Running REINSTALL remove
		remove
		echo [*] Running REINSTALL install
		doinstall
	;;
     *)
                echo -e " install   	- Install the system"
                echo -e " forceinstall  - Install the system without checking for deps"
                echo -e " remove     	- Remove the system"
                echo -e " status     	- Check install status"
                echo -e " reinstall  	- Re-install system"
		echo -e "\n Example:"
		echo -e " $ sudo ./openfpc-install install"
        ;;
esac
