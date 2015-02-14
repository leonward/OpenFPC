Documentation of .openfpc-client.rc file
=========================
leon@openfpc.org

If like me you get annoyed having to type in the same flags over and over again into openfpc-client, you can make use of a .openfpc-client.rc file. Every time you run openfpc-client it looks in your home directory for a file named .openfpc-client.rc, and uses values specified in it for your connection. For example, if you only have one --user and keep connecting to the same --server, why type them every time you want to interact with the daemon?

You can put any of the below in your ~/.openfpc-client.rc file.

- server=
  Set the server address you want to connect to by default
- port=
  Set the port your queue daemon listens on if it's not the default 4242
- action=
  Set the default action
- limit=
  Set an alternative limit on the number of search results returned
- last=
  Set an alternative number of seconds you would like to look back

The format of this file is simple. 
    option=value

Any command line arguments take precedence over those set in the configuration file.

For example:
````
$ cat ~/.openfpc-client.rc
user=bob
server=123.456.789.123
port=4242
action=status
$
````