#!/bin/bash 

# Create a release file for OpenFPC
# It's simple, dirty, and works for me.

# Leon Ward - leon@rm-rf.co.uk

TARPATH=~
SRCPATH=..
PROG_FILES="openfpc-cx2db openfpc-client openfpc-install.sh openfpc openfpc-queued openfpc-dbmaint openfpc-password"
PERL_MODS="Parse.pm Request.pm CXDB.pm Common.pm Config.pm"
#WWW_DIR="www"
#CGI_FILES="extract.cgi"
DOC_FILES="README INSTALL TODO"
ETC_FILES="openfpc-default.conf openfpc-example-proxy.conf routes.ofpc"
INIT_SCRIPTS="openfpc-daemonlogger openfpc-cxtracker openfpc-cx2db openfpc-queued"
VER_FILES="openfpc-install.sh openfpc-client openfpc OFPC/Config.pm openfpc-dbmaint openfpc-cx2db openfpc-password"


echo -e "**** Have you run svn up?"
read foo
echo -e "Checking version numbers in code so I don't forget to ++ something..."
LASTVER=$(grep openfpcver $SRCPATH/openfpc |awk -F = '{print $2}' | awk -F \; '{print $1}')
for i in $VER_FILES
do
	VER=$(grep -i openfpcver $SRCPATH/$i |grep = |awk -F = '{print $2}' |awk -F \; '{print $1}' |sed s/\"//g | sed s/" "*//g)
	[ "$LASTVER" == "$VER" ] || echo "WARNING! Version mismatch!!!!"
	LASTVER="$VER"
	echo -e " $VER - $i"

done	

#MINOR=$(svn info |grep Revision | awk '{print $2}' )
TARGET="$TARPATH/openfpc-$VER"
FILENAME="openfpc-$VER.tgz"

echo -e "* Build Version $VER in $TARPATH ? (ENTER = yes)"
read 

if [ -d $TARGET ]
then
	echo Error $TARGET exists. 
	echo Hit ENTER to rm -rf $TARGET, to stop it CRTL+C
	read 
	rm -rf $TARGET
	exit 1
else
	echo Creating Structure
	mkdir $TARGET
	mkdir $TARGET/OFPC
	mkdir $TARGET/cgi-bin
	mkdir $TARGET/docs
	mkdir $TARGET/etc
	mkdir $TARGET/etc/init.d

	echo -e "* Program Files"	
	for i in $PROG_FILES
	do
		echo -e "- Adding $i to $TARGET"
		cp $SRCPATH/$i $TARGET
	done

#	echo -e "* CGI Files"	
#	for i in $CGI_FILES
#	do
#		echo -e "- Adding $i to $TARGET/cgi-bin"
#		cp $SRCPATH/cgi-bin/$i $TARGET/cgi-bin
#	done

	echo -e "* Perl Modules"	
	for i in $PERL_MODS
	do
		echo -e "- Adding $i to $TARGET/OFPC"
		cp $SRCPATH/OFPC/$i $TARGET/OFPC
	done

	echo -e "* Documentation"	
	for i in $DOC_FILES
	do
		echo -e "- Adding $i to $TARGET/docs"
		cp $SRCPATH/docs/$i $TARGET/docs
	done
	echo -e "* Config files"	
	for i in $ETC_FILES
	do
		echo -e "- Adding $i to $TARGET/etc"
		cp $SRCPATH/etc/$i $TARGET/etc
	done

	echo -e "* Init scripts"	
	for i in $INIT_SCRIPTS
	do
		echo -e "- Adding $i to $TARGET/etc/init.d"
		cp $SRCPATH/etc/init.d/$i $TARGET/etc/init.d
	done


	cd $TARPATH
	tar -czf $FILENAME openfpc-$VER
 	cd -	
fi

echo "Created $TARPATH/$FILENAME"

