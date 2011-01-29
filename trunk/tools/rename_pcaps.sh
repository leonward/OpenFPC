#!/bin/bash -e

# Quick script to rename all pcap files in a directory. Comes in handy if you need to rename your NODENAME.
# - Leon Ward 2011

DIR=$1
OLD_NODE=$2
NEW_NODE=$3
PAUSE=1

if [ $# -ne 3 ] 
then
	echo -e "Incorrect number of args."
	echo -e "Usage:"
	echo -e "$0 <directory> <Old NODENAME> <New NODENAME>"
	exit 1
fi

echo "About to rename all files in $DIR from $OLD_NODE to $NEW_NODE"
echo "Hit Enter to continue, or CRTL+C to break out"
read

for file in $DIR/*
do
	if echo $file |grep $OLD_NODE
	then
		PRE=$(echo $file | awk -F $OLD_NODE '{print $1'})
		POST=$(echo $file | awk -F $OLD_NODE '{print $2'})
		NEWFILE=$PRE$NEW_NODE$POST
		if [ $PAUSE ] 
		then
			echo Press Enter to move $file to $NEWFILE
			read
		else 
			echo Moving $file to $NEWFILE
		fi
		mv $file $NEWFILE
	else
		echo Filename $file out of scope. Does not contain old NODENAME $OLD_NODE
	fi
done
