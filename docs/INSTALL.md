Installing OpenFPC.
=========================

*Last updated Jan 1 2015*

** Contact: leon@openfpc.org **


To install OpenFPC you have two options:

* Use the Ubuntu Packages
  These packages are not part of the Ubuntu distribution, I roll them myself. This should be the easiest way to get started.
* Go grab the source from Github, and install from source using the openfpc-install.sh script.
  If you're using Ubuntu and have a system that can work with the .deb packages, the only advantage of using the openfpc-install.sh script is that it makes it easier to use the most recent code. 

Both installation methods should leave you with a system that functions in the same way, so the choice is yours.

Installing from Source
----------------------

If this is your first time installing OpenFPC and have decided against using the Ubuntu packages, it's wise to start off with a default installation (./openfpc-install.sh install). From there you can get used to how things function, and then customize it as needed. If you know what you're doing and don't want databases and users created automatically for you, take a look at './openfpc-install.sh help' for other options.

The general steps you need to follow for a default install are the below. Each step is also described in detail.

* Install the Ubuntu package dependencies that are in the Ubuntu package archives
  Note that the install script will also check these for you in case you miss any.
* Download & install cxtracker 
* Download OpenFPC code 
* Untar and run the OpenFPC install script (openfpc-install.sh)
  The installer will also do the following things for you:
  - Create a user for OpenFPC and set the password
  - Create the session database
  - Start OpenFPC

That should be it. So go grab a coffee and wait for some packets to come in, then try out some basic searches and traffic extraction.

All of the below sections talk though the details of how to achieve the above.

Install the Ubuntu package dependencies:
----------------------------------------

You'll need to install all of the below packages for OpenFPC to function. If you chose to install from the .deb file, these will be resolved for you thanks to the magic of apt.

```
 $ sudo apt-get install daemonlogger tcpdump tshark libdatetime-perl libprivileges-drop-perl libarchive-zip-perl libfilesys-df-perl mysql-server libdbi-perl libterm-readkey-perl libdate-simple-perl libdigest-sha-perl libjson-pp-perl libdatetime-perl libswitch-perl libdatetime-format-strptime-perl libdata-uuid-perl git
```

Download & Install cxtracker
----------------------------

 Cxtracker is a connection capturing tool designed for general nsm functions. It is written and maintained by Edward Bjarte Fjellskål. In the context of OpenFPC. it finds connections on the network and stores them to disk in a CSV file. A second program (openfpc-cx2db) then parses these session files and uploads them to the OpenFPC session database. This session database allows you to search for network traffic very quickly and identify the sessions you would like to extract. In OpenFPC the connection data is not back-hauled to a central point centrally stored, instead an OpenFPC proxy can aggregate a single search and make it take place across multiple remote nodes (the things capturing session and packet data), it will then combine the results into one dataset for the user.

```
   $ wget http://github.com/downloads/gamelinux/cxtracker/cxtracker_0.9.5-1_i386.deb
```

```
   $ sudo dpkg -i cxtracker_0.9.5-1_i386.deb
```

If cxtracker fails to install due to package dependencies, a simple -f install should fix that for you:

```
   $ sudo apt-get -f install
```

Download OpenFPC.
-----------------

Either download one of the release tarballs, or simply clone the repo if you want the bleeding edge:

```
$ git clone https://github.com/leonward/OpenFPC.git
```

    $ cd OpenFPC

Tarballs can be found at http://leonward.github.com/OpenFPC/releases

Extract and install OpenFPC
-----------------------------

Before you run the installer, there are likely a couple of things you should note.

* The apparmor profile for tcpdump will be disabled.
  Because openfpc-queued needs to use tcpdump to extract session data that is stored on disk, the Ubuntu apparmor profile that prevents it from *reading* files anywhere outside of a users home directory isn't viable. The installer will disable apparmor for tcpdump (and only tcpdump) by creating /etc/apparmor.d/disable/usr.sbin.tcpdump. If you don't want this, make sure you re-enable it, or edit the installer to not do this. Note that you'll have to make sure that all pcap operations take place in the openfpc user's ~, and that's less than ideal for a file organization point of view.
* A node called "Default_Node" is created by default. 
   To change its configuration you can edit /etc/openfpc/openfpc-default.conf. If you're going to change the name of a node, **make sure you stop OpenFPC first**.
* A user called openfpc is added to the system
   This is used by all components to drop privileges to (you don't want daemons running as root)
* Pay attention for any errors that pop up


```
$ sudo ./openfpc-install.sh  install

 *************************************************************************
 *  OpenFPC installer - Leon Ward (leon@openfpc.org) v0.9
 *  A set if scripts to help manage and find data in a large network traffic
 *  archive.

 *  http://www.openfpc.org

[*] Detected distribution as DEBIAN-like

[*] Installing OpenFPC
[-] Checking for daemonlogger ...
    daemonlogger Okay
[-] Checking for tcpdump ...
    tcpdump Okay
[-] Checking for tshark ...
    tshark Okay
[-] Checking for libdatetime-perl ...
    libdatetime-perl Okay
[-] Checking for libprivileges-drop-perl ...
    libprivileges-drop-perl Okay
[-] Checking for libarchive-zip-perl ...
    libarchive-zip-perl Okay
[-] Checking for libfilesys-df-perl ...
    libfilesys-df-perl Okay
[-] Checking for mysql-server ...
    mysql-server Okay
[-] Checking for libdbi-perl ...
    libdbi-perl Okay
[-] Checking for libterm-readkey-perl ...
    libterm-readkey-perl Okay
[-] Checking for libdate-simple-perl ...
    libdate-simple-perl Okay
[-] Checking for libdigest-sha-perl ...
    libdigest-sha-perl Okay
[-] Checking for libjson-pp-perl ...
    libjson-pp-perl Okay
[-] Checking for libdatetime-perl ...
    libdatetime-perl Okay
[-] Checking for libswitch-perl ...
    libswitch-perl Okay
[-] Checking for libdatetime-format-strptime-perl ...
    libdatetime-format-strptime-perl Okay
[-] Checking for libdata-uuid-perl ...
    libdata-uuid-perl Okay
/usr/bin/cxtracker
[*] Found cxtracker in your $PATH (good)
[*] Disabling apparmor profile for tcpdump
 * Reloading AppArmor profiles
Skipping profile in /etc/apparmor.d/disable: usr.sbin.tcpdump            [ OK ]
 -  Installing modules to /usr/local/lib/site_perl
 -  Installing PERL module Parse.pm
 -  Installing PERL module Request.pm
 -  Installing PERL module CXDB.pm
 -  Installing PERL module Common.pm
 -  Installing PERL module Config.pm
 -  Installing OpenFPC Application: openfpc-client
 -  Installing OpenFPC Application: openfpc-queued
 -  Installing OpenFPC Application: openfpc-cx2db
 -  Installing OpenFPC Application: openfpc
 -  Installing OpenFPC Application: openfpc-dbmaint
 -  Installing OpenFPC Application: openfpc-password
 -  Installing OpenFPC conf: etc/openfpc-default.conf
 -  Installing OpenFPC conf: etc/openfpc-example-proxy.conf
 -  Installing OpenFPC conf: etc/routes.ofpc
 -  Installing /etc/init.d//openfpc-daemonlogger
 -  Installing /etc/init.d//openfpc-cx2db
 -  Installing /etc/init.d//openfpc-cxtracker
 -  Installing /etc/init.d//openfpc-queued
[*] Updating init config with update-rc.d
 Adding system startup for /etc/init.d/openfpc-daemonlogger ...
   /etc/rc0.d/K20openfpc-daemonlogger -> ../init.d/openfpc-daemonlogger
   /etc/rc1.d/K20openfpc-daemonlogger -> ../init.d/openfpc-daemonlogger
   /etc/rc6.d/K20openfpc-daemonlogger -> ../init.d/openfpc-daemonlogger
   /etc/rc2.d/S20openfpc-daemonlogger -> ../init.d/openfpc-daemonlogger
   /etc/rc3.d/S20openfpc-daemonlogger -> ../init.d/openfpc-daemonlogger
   /etc/rc4.d/S20openfpc-daemonlogger -> ../init.d/openfpc-daemonlogger
   /etc/rc5.d/S20openfpc-daemonlogger -> ../init.d/openfpc-daemonlogger
[*] Adding user openfpc
 Adding system startup for /etc/init.d/openfpc-cx2db ...
   /etc/rc0.d/K20openfpc-cx2db -> ../init.d/openfpc-cx2db
   /etc/rc1.d/K20openfpc-cx2db -> ../init.d/openfpc-cx2db
   /etc/rc6.d/K20openfpc-cx2db -> ../init.d/openfpc-cx2db
   /etc/rc2.d/S20openfpc-cx2db -> ../init.d/openfpc-cx2db
   /etc/rc3.d/S20openfpc-cx2db -> ../init.d/openfpc-cx2db
   /etc/rc4.d/S20openfpc-cx2db -> ../init.d/openfpc-cx2db
   /etc/rc5.d/S20openfpc-cx2db -> ../init.d/openfpc-cx2db
 Adding system startup for /etc/init.d/openfpc-cxtracker ...
   /etc/rc0.d/K20openfpc-cxtracker -> ../init.d/openfpc-cxtracker
   /etc/rc1.d/K20openfpc-cxtracker -> ../init.d/openfpc-cxtracker
   /etc/rc6.d/K20openfpc-cxtracker -> ../init.d/openfpc-cxtracker
   /etc/rc2.d/S20openfpc-cxtracker -> ../init.d/openfpc-cxtracker
   /etc/rc3.d/S20openfpc-cxtracker -> ../init.d/openfpc-cxtracker
   /etc/rc4.d/S20openfpc-cxtracker -> ../init.d/openfpc-cxtracker
   /etc/rc5.d/S20openfpc-cxtracker -> ../init.d/openfpc-cxtracker
 Adding system startup for /etc/init.d/openfpc-queued ...
   /etc/rc0.d/K20openfpc-queued -> ../init.d/openfpc-queued
   /etc/rc1.d/K20openfpc-queued -> ../init.d/openfpc-queued
   /etc/rc6.d/K20openfpc-queued -> ../init.d/openfpc-queued
   /etc/rc2.d/S20openfpc-queued -> ../init.d/openfpc-queued
   /etc/rc3.d/S20openfpc-queued -> ../init.d/openfpc-queued
   /etc/rc4.d/S20openfpc-queued -> ../init.d/openfpc-queued
   /etc/rc5.d/S20openfpc-queued -> ../init.d/openfpc-queued
==============================================
[*] EASY INSTALL
 -  Step 1: Creating a user to access OpenFPC.
    This user will be able to extract data and interact with the queue-daemon.
    OpenFPC user & password management is controlled by the application openfpc-passwd.
    The default OpenFPC passwd file is /etc/openfpc/openfpc.passwd
[*] Creating new user file /etc/openfpc/openfpc.passwd...
[-] Enter Username: <ENTER A USERNAME>
    Enter new password:
    Retype password:
    Password Okay
[*] Done.
==============================================
[*] Step 2: Creating an OpenFPC Session DB
    OpenFPC uses cxtracker to record session data. Session data is much quicker to search through than whole packet data stored in a database.
    All of the databases used in OpenFPC are controlled by an application called openfpc-dbmaint.
    - Note that you will need to enter the credentials of a mysql user that has privileges to creted/drop databases (most likely root)
[*] openfpc-dbmaint: Create and manage OpenFPC databases
 -  Action: create
 -  Database type: session
 -  Config file: /etc/openfpc/openfpc-default.conf
[*] Enter mysql credentials of an account with that can create/update/drop databases
    DB root Username: root
    DB root Password:
[*] Creating Session database on Default_Node
 -  Session DB Created
 -  Adding function INET_ATON6 to DB ofpc_session_default
[*] Restarting OpenFPC Node Default_Node
Stopping Daemonlogger...                                              Not running
Stopping OpenFPC Queue Daemon (Default_Node)...                       Not running
Stopping OpenFPC cxtracker (Default_Node)...                          Not running
Stopping OpenFPC Connection Uploader (Default_Node)...                Not running
Starting Daemonlogger (Default_Node)...                                    Done
Starting OpenFPC Queue Daemon (Default_Node)...                            Done
Starting OpenFPC cxtracker (Default_Node)...                               Done
Starting OpenFPC Connection Uploader (Default_Node) ...                    Done
[*] Starting OpenFPC
Starting Daemonlogger (Default_Node)...                                 Running
Starting OpenFPC Queue Daemon (Default_Node)...                         Running
Starting OpenFPC cxtracker (Default_Node)...                            Running
Starting OpenFPC Connection Uploader (Default_Node) ...                 Running
==============================================
[*] Installation complete.
Now would be a good time to read of docs/usage.md.
Here are a couple of tips to get started.

  $ openfpc-client -a status --server localhost --port 4242
  $ openfpc-client -a  fetch -dpt 53 --last 600
  $ openfpc-client -a search -dpt 53 --last 600
  $ openfpc-client --help
```

To actually interact with you OpenFPC Node (Default_Node), you can use the openfpc-client. The openfpc-client is a client application that talks with either an OpenFPC Node or OpenFPC Proxy over the network. This allows you to use a local tool on your workstation to search, extract, save and fetch pcaps from the remote device capturing data. By default openfpc-client tries to connect to the server localhost on TCP:4242. Check openfpc-client --help to find out how to specify a remote node (--server --port).

