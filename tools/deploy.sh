#!/bin/bash

# Deply script to push key files on to testing device. 
# Only really useful for my own testing - Leon

TUSER=lward
TDEV=192.168.42.10
TPATH=/home/$USER/openfpc/
PATHCHECK="openfpc-client README.md"
DIRS="cgi-bin docs etc OFPC tools www"
FILES="openfpc-client openfpc-dbmaint openfpc-password openfpc  openfpc-cx2db  openfpc-install.sh openfpc-queued"

VERBOSE=1

function die
{
	echo $1
	exit 1
}
if [ $1 ] ; then

	echo "Deploying to $1"
	TDEV=$1
else 
	echo "Deploying to $TDEV"
fi

if [ $VERBOSE == 1 ] ; then
	echo "* Running in verbose mode"
else
	echo "* Running in silent mode"
fi

# Check we are in the expected location on the disk
# E.g run ./tools/deploy

for i in $PATHCHECK;
do
	[ $VERBOSE == 1 ] && echo "  Checking for file $i"
	[ -e "$i" ] || die "! Cant find $i this script should be run from the openfpc top dir."
done


# Check that the target exists on the remote system 
if $(ssh $TUSER@$TDEV [ -d $TPATH ])
	then
		echo "- Target path $TPATH found on target device $TDEV"
	else
		die "Cant find target path $TPATH on target device $TDEV, won't continue"
fi

for d in $DIRS;
do
	echo "- Copying $d"
	scp -r $d $TUSER@$TDEV:$TPATH/
done

for f in $FILES;
do
	scp $f $TUSER@$TDEV:$TPATH/
done

