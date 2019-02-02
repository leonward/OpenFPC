# OpenFPC Client Installation
If the debian package does not work for you, it is not difficult to install the client manually.
# Install Dependencies
```sh
$ sudo apt-get install libterm-readkey-perl libarchive-zip-perl libfilesys-df-perl libdatetime-perl libdate-simple-perl libswitch-perl libdata-uuid-perl git-core
```
# Make an OFPC directory in the Perl library
```sh
$ sudo mkdir /usr/share/perl5/OFPC
```
# Get OpenFPC code from GitHub
```sh
$ git clone https://github.com/leonward/OpenFPC.git
```
# Copy OFPC Perl modules to the Perl library
This assumes you are in the directory where you executed git clone
```
$ sudo cp OpenFPC/OFPC/Parse.pm /usr/share/perl5/
$ sudo cp OpenFPC/OFPC/Request.pm /usr/share/perl5/
```
# Copy the openfpc-client file to /usr/bin
This assumes you are in the directory where you executed git clone
```
$ sudo cp OpenFPC/openfpc-client /usr/bin
```
# Test
```
$ openfpc-client --help
```
# .openfpc-client.rc file
Read the file OpenFPC/docs/openfpc-client.rc.md.  You can save yourself a lot of typing if you make a .openfpc-client.rc file.
