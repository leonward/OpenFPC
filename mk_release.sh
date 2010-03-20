#!/bin/bash

# Create a release file for OpenFPC
# It's simple, dirty, and works for me.

# Leon Ward - leon@rm-rf.co.uk


echo Checking version numbers in code...
grep openfpcver ./* |grep -v mk_release.sh |awk -F = '{print $2}'
VER=$(grep openfpcver openfpc |awk -F = '{print $2}')


TARPATH=..
FILES="extract-pcap.pl  install-openfpc.sh openfpc openfpc.conf README"
TARGET="$TARPATH/openfpc-$VER"
FILENAME="openfpc-$VER.tgz"
echo -e "* Build Version $VER in $TARPATH ? (ENTER = yes)"

read 

if [ -d $TARGET ]
then
	echo Error $TARGET exists
	exit 1
else
	echo Creating $TARGET
	mkdir $TARGET

	for i in $FILES
	do
		echo -e "- Adding $i to $TARGET"
		cp $i $TARGET
	done
		cd $TARPATH
		tar -czf "$FILENAME" $TARGET
	 	cd -	
fi

echo "Created $TARPATH/$FILENAME"
