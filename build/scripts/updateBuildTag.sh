#!/bin/bash
# $1 : arch
# $2 : Solution directory
# $3 : Version
cd $2
git init
cd drbd

if test -e ../.git && GITHEAD=$(git rev-parse HEAD); then
	ENGVER=v$3
	sed -i "s/\(^#define BUILD_VERSION\).*/\1 \"$ENGVER\"/g" drbd_buildtag.c 
	sed -i "s/\(^#define COMMIT\).*/\1 \"${GITHEAD:0:7}\"/g" drbd_buildtag.c
	sed -i "s/\(^#define BUILD_USER\).*/\1 \"$(id -un)\"/g" drbd_buildtag.c
	sed -i "s/\(^#define BUILD_HOST\).*/\1 \"$HOSTNAME\"/g" drbd_buildtag.c
elif ! test -e drbd_buildtag.c ; then				
	echo >&2 "drbd_buildtag.c not found.";					
	test -e ../../.git &&						
	>&2 printf "%s\n"						
		"git did not work, but this looks like a git checkout?"	
		"Install git and try again." ||				
	echo >&2 "Your DRBD source tree is broken. Unpack again.";	
	exit 1;								
fi ;		