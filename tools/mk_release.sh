#!/bin/bash 

# Create a release file for OpenFPC
# It's simple, dirty, and works for me.

# Leon Ward - leon@rm-rf.co.uk

TARPATH=~
SRCPATH=..
PROG_FILES="openfpc-cx2db openfpc-client openfpc-install.sh openfpc openfpc.conf openfpc-queued openfpc-setup.pl openfpc-dbmaint.sh"
PERL_MODS="Parse.pm Request.pm"
WWW_FILES="index.php bluegrade.png"
CGI_FILES="extract.cgi"
DOC_FILES="README INSTALL TODO"
ETC_FILES="openfpc.apache2.conf openfpc-example-node.conf openfpc-example-proxy.conf routes.ofpc"
INIT_SCRIPTS="openfpc-daemonlogger openfpc-cxtracker openfpc-cx2db openfpc-queued"
VERFILES="openfpc-install.sh openfpc-client openfpc openfpc-queued"

echo -e "Checking version numbers in code so I dont forget to ++ something..."
for i in $VERFILES
do
	VER=$(grep openfpcver $SRCPATH/$i |awk -F = '{print $2}' |awk -F \; '{print $1}')
	echo -e " $VER - $i"
done	

VER=$(grep openfpcver $SRCPATH/openfpc |awk -F = '{print $2}' | awk -F \; '{print $1}')
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
	mkdir $TARGET/www
	mkdir $TARGET/OpenFPC
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
	echo -e "* WWW Files"	
	for i in $WWW_FILES
	do
		echo -e "- Adding $i to $TARGET/www"
		cp $SRCPATH/www/$i $TARGET/www
	done


	echo -e "* CGI Files"	
	for i in $CGI_FILES
	do
		echo -e "- Adding $i to $TARGET/cgi-bin"
		cp $SRCPATH/cgi-bin/$i $TARGET/cgi-bin
	done

	echo -e "* Perl Modules"	
	for i in $PERL_MODS
	do
		echo -e "- Adding $i to $TARGET/OpenFPC"
		cp $SRCPATH/OpenFPC/$i $TARGET/OpenFPC
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

