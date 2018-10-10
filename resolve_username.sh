#!/usr/bin/env bash

email=$1

username="$(ldapsearch -H ldaps://ldap.embl.de -b cn=Users,dc=embl,dc=org -x mail=$email uid | sed -n 's/uid: //p')"

if [[ ! -z "${username// }" ]]; then
   echo "$username"
else
   echo "scholtalbers"
   #echo "${email%@*}"
fi
