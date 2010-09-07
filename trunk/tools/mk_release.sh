#!/bin/bash 

# Create a release file for OpenFPC
# It's simple, dirty, and works for me.

# Leon Ward - leon@rm-rf.co.uk

TARPATH=~
SRCPATH=..
PROG_FILES="ofpc-client.pl install-ofpc.sh openfpc openfpc.conf ofpc-queued.pl setup-ofpc.pl"
PERL_MODS="Parse.pm Request.pm"
WWW_FILES="index.php bluegrade.png"
CGI_FILES="extract.cgi"
DOC_FILES="README INSTALL TODO"
ETC_FILES="openfpc.apache2.conf"
VERFILES="install-ofpc.sh ofpc-client.pl openfpc ofpc-queued.pl"

echo -e "Checking version numbers in code so I dont forget to ++ something..."
for i in $VERFILES
do
	VER=$(grep openfpcver $SRCPATH/$i |awk -F = '{print $2}')
	echo -e " $VER - $i"
done	

VER=$(grep openfpcver $SRCPATH/openfpc |awk -F = '{print $2}')
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
	mkdir $TARGET/ofpc
	mkdir $TARGET/cgi-bin
	mkdir $TARGET/docs
	mkdir $TARGET/etc

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
		echo -e "- Adding $i to $TARGET/ofpc"
		cp $SRCPATH/ofpc/$i $TARGET/ofpc
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

	cd $TARPATH
	tar -czf $FILENAME openfpc-$VER
 	cd -	
fi

echo "Created $TARPATH/$FILENAME"

