#!/usr/bin/env bash

username=$1
email=$2


# If your galaxy usernames do not match the unix usernames, then fix it here with your custom code like below

echo $username
exit 0

# Example:
username="$(ldapsearch -H ldaps://ldap.embl.de -b cn=Users,dc=embl,dc=org -x mail=$email uid | sed -n 's/uid: //p')"

if [[ ! -z "${username// }" ]]; then
   echo "$username"
else
   echo "${email%@*}"
fi
