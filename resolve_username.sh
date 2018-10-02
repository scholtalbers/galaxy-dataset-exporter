#!/usr/bin/env bash

email=$1

if username="$(ldapsearch -H ldaps://ldap.embl.de -b cn=Users,dc=embl,dc=org -x mail=$email uid | sed -n 's/uid: //p')"; then
   #echo "$username"
   echo "scholtalbers"
else
   splitted=(${email//@/})
   echo "${splitted[0]}"
fi