#!/bin/bash

# Deply script to push key files on my local testing device. 
# Only really useful in my own world here - Leon

TUSER=lward
TDEV=192.168.42.10
TPATH=/home/$TUSER/openfpc/
PATHCHECK="openfpc-client README.md"
DIRS="openfpc-restapi docs etc OFPC tools"
FILES="openfpc-client openfpc-dbmaint openfpc-password openfpc openfpc-cx2db openfpc-install.sh openfpc-queued"
VERBOSE=1

function die
{
	echo $1
	exit 1
}

function deploy
{
	echo -e "[*] Deploying to $1"
	# Check that the target exists on the remote system 
	if $(ssh $TUSER@$TDEV [ -d $TPATH ])
		then
			echo "- Target path $TPATH found on target device $TDEV"
		else
			die "Cant find target path $TPATH on target device $TDEV, won't continue"
	fi

	for f in $FILES;
	do
		scp $f $TUSER@$TDEV:$TPATH/
	done
	
	for d in $DIRS;
	do
		echo "- Copying $d"
		scp -r $d $TUSER@$TDEV:$TPATH/
	done

	
}

if [ $1 ] ; then

	echo "Deploying to devices."
	TDEV=$1
else 
	die "Usage: deploy <device IP>"
	
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

for i in $@
do
	echo $i
	TDEV=$i
	echo "Deploying to $TDEV"
	deploy $TDEV
done 

