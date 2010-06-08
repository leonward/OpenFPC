#!/bin/bash

# Create a release file for OpenFPC
# It's simple, dirty, and works for me.

# Leon Ward - leon@rm-rf.co.uk

TARPATH=..
FILES="ofpc-extract.pl install-openfpc.sh openfpc openfpc.conf README ofpcParse.pm"
VERFILES="install-openfpc.sh ofpc-extract.pl openfpc"

echo Checking version numbers in code...
for i in $VERFILES
do
	VER=$(grep openfpcver $i |awk -F = '{print $2}')
	echo -e " $VER - $i"
done	

VER=$(grep openfpcver openfpc |awk -F = '{print $2}')
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
		tar -czf $FILENAME openfpc-$VER
	 	cd -	
fi

echo "Created $TARPATH/$FILENAME"
