#!/bin/bash

function testFile() {

	if [ -f $1 ] ; then
		echo "Warning: This machine is not clear!"
		echo "File $1 still exists!"
		exit
	fi
}

if [ ! "$1" == "-f" ] ; then

	numSrv=`ls /var/onionmail/*/server.bin 2>/dev/null | egrep -ic 'server\.bin'`
	bootS=`ls /var/onionmail/*/head/boot 2>/dev/null | egrep -ic 'boot'`
	if [ "$numSrv" -gt "$bootS" ] ; then
			echo "Incomplete PUSH/DERK operations for some servers."
			echo "Use -f paramter to force wipe files."
			exit
	fi
	
fi

for danger in `ls /var/onionmail/*/sysop.txt 2>/dev/null`
do
        wipe -fs $danger
done

for danger in `ls /var/onionmail/*/keyblock.txt 2>/dev/null`
do
        wipe -fs $danger
done

wipe -fs __PAR_ROOT__/root.txt 2>/dev/null

if [ -f __PATH__/gen.sh ] ; then
	wipe -fs __PATH__/gen.sh 2>/dev/null
	echo "Find: gen.sh Are the server generation complete?"
fi

if [ -f __RAMPASS__ ] ; then
        wipe -fs __RAMPASS__ 2>/dev/null
	echo "Find: BOOT Password in RAM."
fi

testFile __PATH__/gen.sh
testFile __RAMPASS__
testFile __PAR_ROOT__/root.txt



echo "System clear"

