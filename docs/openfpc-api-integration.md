# RestAPI Usage

OpenFPC has a simple API that is used to interact with the queue daemon, this enabled external systems to ask OpenFPC to provide any of the following things:

 - A pcap file of the traffic requested (pass the API it session identifiers or a bpf)
 - A JSON object of all flows, or defined subset of flows, that match the search constraints. This means that OpenFPC has these full packet sessions available for extraction
 - To extract a pcap from the buffer, save it remotely, and return a reference of a filename that can be used to download the file when it is available
 - The status of your OpenFPC system(s)


* API key *

Authentication is handled by a simple API key. All OpenFPC users have a unique API key for identification, the API key for a user can be returned with the openfpc-client command apikey. 

````
vagrant@vagrant-ubuntu-trusty-64:~/OpenFPC$ ./openfpc-client -a apikey

   * openfpc-client 0.9 *
     Part of the OpenFPC project - www.openfpc.org

Username: someuser
Password for user somepass :
#####################################
OpenFPC API key for user g: 11114-11111-1111-B233-8E42545D2F96

````

The API key is passed with the option apikey=xxxxxx, and is required for all requests.


* API URL *

By default the API runs over TCP:4222, and uses TLS for encryption. The SSL key that is generated at boot is self-signed and therefore needs to be replaced with a key you trust.

Path: 
http://localhost:4222/api/1

Functions
=========

* Status *
http://localhost:4222/api/1/status

Arguments:
Required: apikey=<apikey>
Example: 

````
$curl -k localhost:4222/api/1/status?apikey=085F21DA-D15D-11E4-A13Q-933864F21C59

   "nodelist" : [
      "Default_Node"
   ],
   "success" : {
      "val" : 1,
      "type" : "t",
      "text" : "Request Status                 "
   },
   "message" : "None",
   "proxy" : 0,
   "Default_Node" : {
      "firstpacket" : {
         "text" : "Oldest packet in storage       ",
         "val" : "1427115786",
         "type" : "e"
      },
      "saveused" : {
         "text" : "Space used in the save path    ",
         "type" : "b",
         "val" : 1530112
      },
      "sessioncount" : {
         "text" : "Number of sessions in Database ",
         "val" : "60",
         "type" : "t"
      },
      "sessionlag" : {
         "val" : 0,
         "type" : "t",
         "text" : "Number of session files lagging"
      },
      "ld5" : {
         "text" : "Load average 5                 ",
         "val" : "0.03",
         "type" : "t"
      },
      "message" : {
         "val" : 0,
         "type" : "t",
         "text" : "Message                        "
      },
      "success" : {
         "text" : "Request Status                 ",
         "val" : 1,
         "type" : "t"
      },
      "sessionspace" : {
         "text" : "Session storage utilization    ",
         "val" : 4,
         "type" : "p"
      },
      "localtime" : {
         "val" : 1427375109,
         "type" : "e",
         "text" : "Local time on node             "
      },
      "ofpctype" : {
         "text" : "Node Type                      ",
         "type" : "t",
         "val" : "NODE"
      },
      "packetpacptotal" : {
         "val" : "5.3M",
         "type" : "t",
         "text" : "PCAP file space used           "
      },
      "packetspace" : {
         "val" : 4,
         "type" : "p",
         "text" : "Packet storage utilization     "
      },
      "lastctx" : {
         "text" : "Newest session in storage      ",
         "type" : "e",
         "val" : "1427374979"
      },
      "comms" : {
         "text" : "Communication with nodes       ",
         "type" : "t",
         "val" : 0
      },
      "firstctx" : {
         "val" : "1427373299",
         "type" : "e",
         "text" : "Oldest session in storage      "
      },
      "ld15" : {
         "val" : "0.05",
         "type" : "t",
         "text" : "Load average 15                "
      },
      "description" : {
         "text" : "Description                    ",
         "val" : "\"An OpenFPC node. www.openfpc.org\"",
         "type" : "t"
      },
      "packetused" : {
         "val" : 1530112,
         "type" : "b",
         "text" : "Packet storage used            "
      },
      "sessiontime" : {
         "type" : "t",
         "val" : "0 Days, 0 Hours, 28 Minutes, 0 Seconds",
         "text" : "Storage Window                 "
      },
      "savespace" : {
         "type" : "p",
         "val" : "4",
         "text" : "Space available in save path   "
      },
      "nodename" : {
         "text" : "Node Name                      ",
         "type" : "t",
         "val" : "Default_Node"
      },
      "ld1" : {
         "text" : "Load Average 1                 ",
         "type" : "t",
         "val" : "0.03"
      },
      "nodetz" : {
         "text" : "Node Timezone                  ",
         "val" : "UTC",
         "type" : "t"
      },
      "sessionused" : {
         "text" : "Session storage used           ",
         "type" : "b",
         "val" : 1530112
      },
      "ltz" : {
         "text" : "Local time on node             ",
         "type" : "e",
         "val" : 0
      }
   },
   "nodename" : "Default_Node"
}

````

*fetch*
Ask for extraction of a pcap, wait while the extraction takes place, and then download the pcap file.

Arguments:
* Required: apikey=<apikey>
- sip = Source IP address. E.g 192.168.0.1
- dip = Destination IP address. E.g. 192.168.0.2
- spt = Source port. E.g. 53
- dpt = Destination port. E.g. 53
- proto = Protocol. TCP/UDP/ICMP
- bpf = bpf to extract
- stime = Start time
- etime = End timestamp
- timestamp = Single timestamp where an event took place. x seconds before/after will be also extracted
  All timestamp formats that are supported by OpenFPC client are also supported by the API.

Only use a BPF or session identifiers.

Example:
````
curl -k localhost:4222/api/1/fetch?apikey=085F21DA-D15D-11E4-A13B-933864F21C59\&dpt=53\&timestamp=Thu%2026%20Mar%202015%2013:13:55%20GMT > file.pcap
````

*Search*
Search for sessions in the session DB.

* Required: apikey=<apikey>
- sip = Source IP address. E.g 192.168.0.1
- dip = Destination IP address. E.g. 192.168.0.2
- spt = Source port. E.g. 53
- dpt = Destination port. E.g. 53
- proto = Protocol. TCP/UDP/ICMP
- stime = Start time
- stime = End timestamp
- timestamp = Single timestamp where an event took place. x seconds before/after will be also extracted
  All timestamp formats that are supported by OpenFPC client are also supported by the API.

Example:
````
[13:22:54]leonward@brain~$ curl -k localhost:4222/api/1/search?apikey=085F21DA-D15D-11E4-A13B-933864F21C59\&dpt=53\&timestamp=Thu%2026%20Mar%202015%2013:13:55%20GMT

{"dtype":["udt","ip","port","ip","port","protocol","bytes","bytes","bytes","text"],"sql":"SELECT start_time,INET_NTOA(src_ip),src_port,INET_NTOA(dst_ip),dst_port,ip_proto,src_bytes, dst_bytes,(src_bytes+dst_bytes) as total_bytes\n\tFROM session IGNORE INDEX (p_key) WHERE unix_timestamp(CONVERT_TZ(`start_time`, '+00:00', @@session.time_zone))  \n\tbetween 1427372594 and 1427376194 AND dst_port='53' ORDER BY start_time DESC LIMIT 20","nodelist":["Default_Node"],"cols":["Start Time","Source IP","sPort","Destination","dPort","Proto","Src Bytes","Dst Bytes","Total Bytes","Node Name"],"error":0,"nodename":"Default_Node",
"title":"Custom Search","etime":"1427376194","stime":"1427372594",
"size":"17",
"table":{
"0":["2015-03-26 13:18:59","10.0.2.15","56754","10.0.2.3","53","17","152","414","566","Default_Node"],
"6":["2015-03-26 12:58:59","10.0.2.15","53619","10.0.2.3","53","17","152","414","566","Default_Node"],
"4":["2015-03-26 13:02:59","10.0.2.15","56496","10.0.2.3","53","17","152","414","566","Default_Node"],
"15":["2015-03-26 12:34:59","10.0.2.15","46961","10.0.2.3","53","17","304","828","1132","Default_Node"],
"13":["2015-03-26 12:35:02","10.0.2.15","43873","10.0.2.3","53","17","81","150","231","Default_Node"],
"1":["2015-03-26 13:14:59","10.0.2.15","34982","10.0.2.3","53","17","152","414","566","Default_Node"],
"7":["2015-03-26 12:54:59","10.0.2.15","60665","10.0.2.3","53","17","152","414","566","Default_Node"],
"16":["2015-03-26 12:34:59","10.0.2.15","48934","10.0.2.3","53","17","148","353","501","Default_Node"],
"14":["2015-03-26 12:35:01","10.0.2.15","59539","10.0.2.3","53","17","156","361","517","Default_Node"],
"3":["2015-03-26 13:06:59","10.0.2.15","42059","10.0.2.3","53","17","152","414","566","Default_Node"],
"9":["2015-03-26 12:44:42","10.0.2.15","51235","10.0.2.3","53","17","81","150","231","Default_Node"],
"12":["2015-03-26 12:35:06","10.0.2.15","33958","10.0.2.3","53","17","81","150","231","Default_Node"],
"8":["2015-03-26 12:50:59","10.0.2.15","59007","10.0.2.3","53","17","152","414","566","Default_Node"],
"2":["2015-03-26 13:10:59","10.0.2.15","36854","10.0.2.3","53","17","152","414","566","Default_Node"],
"10":["2015-03-26 12:42:59","10.0.2.15","48935","10.0.2.3","53","17","152","414","566","Default_Node"],
"5":["2015-03-26 13:00:02","10.0.2.15","53079","10.0.2.3","53","17","81","150","231","Default_Node"],
"11":["2015-03-26 12:35:11","10.0.2.15","34215","10..2.3","53","17","296","706","1002","Default_Node"]
},"format":[22,18,8,18,8,8,14,14,14,20],"type":"search"}
````

*store*
Request an extraction the file from the remote pcap store and disconnect. The extraction will take place and will be saved to a the filename returned".

Arguments: 
* Required: apikey=<apikey>
- sip = Source IP address. E.g 192.168.0.1
- dip = Destination IP address. E.g. 192.168.0.2
- spt = Source port. E.g. 53
- dpt = Destination port. E.g. 53
- proto = Protocol. TCP/UDP/ICMP
- bpf = bpf to extract
- stime = Start time
- stime = End timestamp
- timestamp = Single timestamp where an event took place. x seconds before/after will be also extracted
  All timestamp formats that are supported by OpenFPC client are also supported by the API.

Only use a BPF or session identifiers.

Returns:
message : Response from the queue daemon performing the extraction. Likely in queue
success : 1 = queued, 0 = fail
rid 	: UUID for the request. Enables you to download the file later.
position: Place in the extraction queue
filename: Auto-generated filename that will be used to save the file.

````
13:37:20]leonward@brain~$ curl -k localhost:4222/api/1/store?apikey=085F21DA-D15D-11E4-A13B-933864F21C59\&dpt=53
{
   "message" : "In Queue",
   "success" : 1,
   "rid" : "73B23C4E-D3BD-11E4-8EBB-5B162C44E780",
   "position" : "0",
   "filetype" : 0,
   "md5" : 0,
   "filename" : "73B23C4E-D3BD-11E4-8EBB-5B162C44E780.pcap",
}
```

*retrieve*
Retrieve a pcap that has been stored on the remote system.
Arguments: 
* Required: apikey=<apikey>
* Required: rid=<request ID>

Note that a request ID is returned for every store request.

Example:
````
curl localhost:4222/api/1/retrieve?apikey=085F21DA-D15D-11E4-A13B-933864F21C59\&rid=39FBE798-D3BD-11E4-8EBB-5B162C44E780 > /tmp/fpcap
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 15924  100 15924    0     0  1588k      0 --:--:-- --:--:-- --:--:-- 1727k
````

