#!/bin/bash

function testFile() {
	echo -ne "  $2:\t"
	if [ -f $1 ] ; then
		echo "Present"
	else
		echo "Absent"
	fi
}

numSrv=`ls /var/onionmail/*/server.bin 2>/dev/null | egrep -ic 'server\.bin'`
friend=`ls /var/onionmail/*/friends 2>/dev/null | egrep -ic 'friends'`
bootS=`ls /var/onionmail/*/head/boot 2>/dev/null | egrep -ic 'boot'`
dangS=`ls /var/onionmail/*/sysop.txt 2>/dev/null | egrep -ic 'sysop'`
dangK=`ls /var/onionmail/*/keyblock.txt 2>/dev/null | egrep -ic 'keyblock'`
netMapS=`ls /var/onionmail/*/feed/network 2>/dev/null | egrep -ic 'network'`

echo "Dangerous files:"
testFile __RAMPASS__ "Boot Pass."
testFile __PAR_ROOT__/root.txt "Root Info"
testFile __PATH__/gen.sh "gen.sh"

echo -e "\nDangerous files: sysop.txt"
for danger in `ls /var/onionmail/*/sysop.txt 2>/dev/null`
do
        echo $danger
done

echo -e "\nDangerous files: keyblock.txt"
for danger in `ls /var/onionmail/*/keyblock.txt 2>/dev/null`
do
        echo $danger
done

echo -e "\nStatus of servers:"
for stat in `ls /var/onionmail/*/status 2>/dev/null`
do
        echo $stat
        cat $stat
        echo ""
done

echo -e "\nNetwork JAVA listening:"
netstat -napW | grep java

echo -e "\nBoot Password file:"
echo -e "\t__RAMPASS__\n"
echo "Server's base path:"
echo -e "\t__MAILDIR__\n"
echo -e "Server's CLI:\t127.0.0.1:__CTRL__"

echo -e "\tOnionMail status:"
echo -e "$numSrv\tServers available."
echo -e "$bootS\tServers with complete PUSH/DERK network."
echo -e "$friend\tServers with complete friends network."
echo -e "$netMapS\tServers with complete network map."
echo -e "$dangS\tServers with sysop.txt"
echo -e "$dangK\tSetvers with keyblock.txt"
