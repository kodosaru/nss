#!/bin/bash
# Install script for NSS
# donj 20140101

date=`date '+%Y%m%d'`
os=`uname`
if [ -f /etc/redhat-release ]
then
	echo "This is a Redhat system"
	redhat=1
else
	redhat=0
fi
if [ "`uname -v | grep -o Ubuntu`" == "Ubuntu" ]
then
	echo "This is a Ubuntu system"
	ubuntu=1
else
	ubuntu=0
fi

# Install program, configuration file and create initial baselines 
if [ "$os" == "SunOS" ]
then
	cp -v nss.solaris.conf /etc/
	chmod 0600 /etc/nss.solaris.conf
	cronfile="/var/spool/cron/crontabs/root"
elif [ "$os" == "Linux" ]
then
	if [ $redhat -eq 1 ]
	then
		cp -v nss.redhat.conf /etc/
		chmod 0600 /etc/nss.redhat.conf
		cronfile="/var/spool/cron/root"
	elif [ $ubuntu -eq 1 ]
	then
		cp -v nss.ubuntu.conf /etc/
		chmod 0600 /etc/nss.ubuntu.conf
		cronfile="/var/spool/cron/crontabs/root"
	else
		echo "Linux OS, but neither Redhat nor Ubuntu"
		exit 1
	fi
else
	echo "Unknown operating system: $os"
	exit 1
fi

if [ ! -d /usr/local/bin ];then
	mkdir -p /usr/local/bin
fi
cp -v nss.pl /usr/local/bin
chmod 0700 /usr/local/bin/nss.pl
/usr/local/bin/nss.pl -b

echo "Installed NSS program and configuration file"

# Create cron job
if [ -f $cronfile ]
then
	cronjob=`cat $cronfile |grep "nss.pl"`
	if [ -z "$cronjob" ]
	then
		printf "\n# Run NSS Security Scanner - nss.pl\n" > /tmp/cronline
		printf "00 08 * * * /usr/local/bin/nss.pl\n" >> /tmp/cronline	
		cp $cronfile $cronfile"."$date
		cat $cronfile /tmp/cronline > /tmp/new_cronfile
		mv -f /tmp/new_cronfile $cronfile 
		if [ $? -eq 0 ]
		then
			echo "Cron job added"
		fi
		rm /tmp/cronline
	else
		echo "Cron job already exists for nss.pl"
	fi
else
		printf "# Run NSS Security Scanner - nss.pl\n" > /tmp/cronline
		printf "00 08 * * * /usr/local/bin/nss.pl\n" >> /tmp/cronline	
		mv /tmp/cronline $cronfile 
		if [ $? -eq 0 ]
		then
			echo "Cron job added"
		fi
fi
