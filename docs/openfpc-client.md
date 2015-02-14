OpenFPC Client Documentation
===========================

**Leon Ward**

**Document is work in progress**


#Getting Started with openfpc-client

This guide is designed to walk a new user though working with the OpenFPC client tool (openfpc-client), the main way to interact with different remote capture points. The OpenFPC client is designed to be used on an analyst workstation where you want to be able to pull down packet logs and investigate things. You don't need to have the full OpenFPC service stack (queue daemon, daemonlogger, database etc) on the same device. 


#Contents
- Installing openfpc-client on your local workstation
- [Authentication](#authentication)
- [Actions](#actions)
  [status](#status)
  [fetch](#fetch)
  [search](#search)
  [store](#store)
- [Traffic Constraints for extraction](#trafficConstraints)
- Searching for sessions
- Specifying a time window and timestamps
- The .openfpc-client.rc file


Authentication
==============

Before you can connect to the OpenFPC queue daemon, you'll need to know the following details:
  - Your username (for the OpenFPC Queue daemon)
  - Password
  - The IP address of the OpenFPC queue daemon
  - The TCP port that the OpenFPC daemon is listening on (default is TCP:442)

The command line arguments to pass all of the details for the above are pretty simple to remember:
 - --user
 - --password
 - --server (defaults to 127.0.0.1 if not specified)
 - --port (defaults to 4242 if not specified)

````
    $ ./openfpc-client --user $USERNAME --password $PASSWORD --server $IP_ADDR --port $PORT
````

The creation and management of users is handled on the OpenFPC node using the openfpc-passwd command. 
You can also use a ~/.openfpc-client.rc file to tweak the defaults above so you don't need to keep typing them in all of the time. 
  
Actions
========
There are many actions that can be taken on an OpenFPC node, the core ones to get familiar with first status, fetch and search. To specify an action, the command argument --action "action" is used, for example:

    $ openfpc-client --action status

###Status
When requested from a node, the Status action return the status of the queue daemon and some basic platform data. When requested from a proxy, the status command will return status data of all connected nodes. Many of the status lines are self explanatory, however some are a little more cryptic. Below each is explained.

- **Node Type:**
  This is the type of node. It will be either NODE or PROXY.

- **Description:**
  Optional text description of the Node. This is specified in the node configuration file.

- **Packet storage utilization:**
  This is the percentage of space used on the partition defined to be used for packet storage.
  By default the location /var/tmp/openpfc/pcap is used, however it makes sense to put this on it's own large storage partition if possible. It is controlled in the config file with the value BUFFER_PATH

- **Session storage utilization:**
  This is the percentage of space used on the partition where temporary session files are written before being added to the mysql database.

- **Space available in save path:**
  This is the percentage of space used on the partition defined to be used for saving extracted pacp files. It is controlled in the OpenFPC config file with the value SAVEDIR=<location>. By default /var/tmp/openfpc/extracted is used.

- **Space used in the save path:**
  This is the amount of space (in Bytes) that is still available in the SAVEPATH partition.

- **Session storage used:**
  This is the amount of space (in Bytes) that is still available in the SESSION_DIR partition.

- **Packet storage used:**
  This is the amount of space (in Bytes) that is still available in the BUFFER_PATH partition.

- **PCAP file space used**
  This is the amount of space (in Bytes) that makes up all of the pcap files that are active on this node. This is similar to Packet storage used, however there are cases where other files may be on the parition.

- **Local time on node**
  Time shows the local time on the node in unix timestamp format, and is also translated into your own local timezone (this may be different to the TZ of the remote node!)

- **Newest session in storage**
  Timestamp of the most recent session added to the session database, also translated into your local timezone.

- **Oldest session in storage**
  This is the timestamp of the oldest session in the session database.

- **Oldest packet in storage**
  This is the timestamp of the oldest packet in the storage buffer.

- **Storage Window:**
  This is the window of all the pcap data that is available for extraction. This assumes that the data is contiguous and this is a dangerous assumption. This is essentially the time delta between $lastpacket and $firstpacket. So if your buffer has been off and not capturing for some time there could be a big gap of data between the timestamps. It does however provide a pretty good idea of the size of the buffer available.

- **Load Average 1, 5, 15** 
  UNIX load average values on the node

- **Number of session files lagging** 
  Connection data is dumped into the SESSION_DIR, and then read/uploaded into the database. If there is ever more than one file lagging there could be something going wrong with inserting data to the DB.

- **Number of sessions in Database** 
  The count of sessions in the session database on that node 

- **Node Timezone** 
  Local Timezone of the remote node. 

Example:
````
$ ./openfpc-client --action status --user admin --server 127.0.0.1
* Reading configuration from /home/lward/.openfpc-client.rc

   * openfpc-client 0.9 *
     Part of the OpenFPC project - www.openfpc.org

Password for user admin :
=====================================
 Status from: Home_Node
=====================================
 * Node: Home_Node
   - Node Type                       : 	 NODE
   - Description                     : 	 "Home Test Node"
   - Packet storage utilization      : 	 83 %
   - Session storage utilization     : 	 9 %
   - Space available in save path    : 	 9 %
   - Space used in the save path     : 	 4391512 (4.39 GB)
   - Session storage used            : 	 4391512 (4.39 GB)
   - Packet storage used             : 	 32369508 (32.37 GB)
   - PCAP file space used            : 	 31G
   - Local time on node              : 	 1420469999 (Mon Jan  5 14:59:59 2015 Europe/London)
   - Newest session in storage       : 	 1420469924 (Mon Jan  5 14:58:44 2015 Europe/London)
   - Oldest session in storage       : 	 1420049832 (Wed Dec 31 18:17:12 2014 Europe/London)
   - Oldest packet in storage        : 	 1420049832 (Wed Dec 31 18:17:12 2014 Europe/London)
   - Storage Window                  : 	 4 Days, 20 Hours, 41 Minutes, 32 Seconds
   - Load Average 1                  : 	 0.00
   - Load average 5                  : 	 0.01
   - Load average 15                 : 	 0.05
   - Number of session files lagging : 	 0
   - Number of sessions in Database  : 	 116463
   - Node Timezone                   : 	 Europe/London
````

###fetch

The fetch action will fetch the full session data you specify and save it on your local device. To fetch sessions 
you will need to specify at least one session identifier and a timewindow to look over.
- For time window constraints look at the 'specifying a time window' section

##Extract constraints [#trafficConstraints]##

The following command line options can be used to define the sessions you would like to extract:

-sip or --src-addr: The IP source address
-dip or --dst-addr: The IP destination address
-spt or --src-port: The source port
-dpt or --dst-port: The destination port
--proto: The protocol to limit the extraction to

The above session identifiers can be mixed, for example the below can find all UDP traffic to port 53 on 8.8.8.8 in the last 60 seconds. For more information on time take a look at the 'specifying a time window' section.

    $ ./openfpc-client --action fetch -dpt 53 -dip 8.8.8.8 --last 60


For more advanced fetching of data, consider using a --bpf. You can't mix --bpf with any of the above session identifiers. --bpf will take precedence. Remember to enclose your bpf in single quotes, for example:

    $ ./openfpc-client -a fetch --bpf 'udp port 53 and host 8.8.8.8' --last 60

When fetching pcap data, there are other aurgmention you may want to also specify.

  - **-w / --write**
  This is a filename to write the pcap data to. For example --write ./myfile. Note that the extension is added by the openfpc client based on teh format of the file returned. Normally this will just be .pcap, however a .zip file is also possible

````
[11:06:20]lward@drax~/code/OpenFPC$ ./openfpc-client -a fetch --bpf 'udp port 53 and host 8.8.8.8' --last 60 -w myfile
* Reading configuration from /Users/lward/.openfpc-client.rc

   * openfpc-client 0.9 *
     Part of the OpenFPC project - www.openfpc.org

Password for user leon :
#####################################
Date    : Sat Feb 14 11:06:36 2015
Filename: myfile.pcap
Size    : 4.9K
MD5     : 102262ba70769e8ca1f0e5d64fd682b8
[11:06:39]lward@drax~/code/OpenFPC$
````

 - **--comment**
 Adds a comment to the extraction. This comment is stored in the server side logs to help justify why an extraction took place, useful for combining extractions to specific incidents. The comment is also included when a zip format file is requested at extract time (see below).

 - **--zip or -Z**
 This option asks the queue daemon to respond with a zip file containing more data about the pcap that has been extracted. This extra data includes any optional comments made by the analyst and hash data of the pcap to help handle legal hearsay issues (IANAL).

````
11:12:20]lward@drax~/code/OpenFPC$ ./openfpc-client -a fetch --bpf 'udp port 53 and host 8.8.8.8' --last 60 -w myfile --zip --comment "This is an example extraction that will show up in the openfpc-client documentation on github"
* Reading configuration from /Users/lward/.openfpc-client.rc

   * openfpc-client 0.9 *
     Part of the OpenFPC project - www.openfpc.org

Password for user leon :
#####################################
Date    : Sat Feb 14 11:14:40 2015
Filename: myfile.zip
Size    : 4.2K
MD5     : f830ee59a6065c7e344f124a14d1005d
[11:14:43]lward@drax~/code/OpenFPC$ unzip myfile.zip
Archive:  myfile.zip
  inflating: 1423912421-883F129C-B43A-11E4-9972-4C26DC081D9D.pcap.txt
  inflating: 1423912421-883F129C-B43A-11E4-9972-4C26DC081D9D.pcap
[11:14:47]lward@drax~/code/OpenFPC$ cat 1423912421-883F129C-B43A-11E4-9972-4C26DC081D9D.pcap.txt
Extract Report - OpenFPC Node 'Home Test Node'
User: leon
Filename: myfile
MD5: b8efce32c9432056d6b509bea02c3ea1
Size: 21K
User comment: This is an example extraction that will show up in the openfpc-client documentation on github
Time: Sat Feb 14 11:13:41 2015
[11:14:52]lward@drax~/code/OpenFPC$ md5 1423912421-883F129C-B43A-11E4-9972-4C26DC081D9D.pcap
MD5 (1423912421-883F129C-B43A-11E4-9972-4C26DC081D9D.pcap) = b8efce32c9432056d6b509bea02c3ea1
[11:15:43]lward@drax~/code/OpenFPC$
````


Specifying a time window
-------------------------



