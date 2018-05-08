#!/bin/bash

score=0
vulns=0
totalVulns=0

echo > /srv/.score.html

tallyVuln() {
   totalVulns=$(($totalVulns+1))
}
score() {
   score=$(($2+$score))
   vulns=$(($vulns+1))
   echo "<p>" >> /srv/.score.html
   echo "$1 - $2</p>" >> /srv/.score.html
}

goodUsers=() #put authorized users in here, seperated by space
badUsers=() #put bad users in here, seperated by space
goodAdmins=() #put good admins in here, seperated by space
badAdmins=() #put bad admins in here, seperated by space
requiredServices=() #add required services in here
requiredPackages=() #add required packages in here
badServices=() #add bad services/proceses in here
badPackages=() #add bad packages in here
goodFiles=() #add verified/required files in here
badFiles=() #add files that should be removed in here


for i in ${goodUsers[@]}; do
   if ! [[ "$(cut -d: -f1 /etc/passwd | grep $i)" ]]; then
      score "Authorized user $i removed" -3
   fi
done

for i in ${badUsers[@]}; do
   tallyVuln
   if ! [[ "$(cut -d: -f1 /etc/passwd | grep $i)" ]]; then
      score "Unauthorized user $i removed" 1
   fi
done

for i in ${goodAdmins[@]}; do
   if ! [[ "$(grep sudo /etc/group | grep $i)" ]]; then
      score "Authorized admin removed from administrators" -3
   fi
done

for i in ${badAdmins[@]}; do
   tallyVuln
   if ! [[ "$(grep sudo /etc/group | grep $i)" ]]; then
      score "Unauthorized user removed from administrators" 2
   fi
done

for i in ${requiredServices[@]}; do
   if ! [[ "$(ps aux | grep -i $i | grep -v grep)" ]]; then
      score "Authorized service $i stopped" -5
   fi
done

for i in ${requiredPackages[@]}; do
   if ! [[ "$(dpkg -l | grep $i | grep ii)" ]]; then
      score "Authorized package $i removed" -5
   fi
done

for i in ${badServices[@]}; do
   tallyVuln
   if ! [[ "$(ps aux | grep -i $i | grep -v grep)" ]]; then
      score "Unauthorized service $i stopped" 3
   fi
done

for i in ${badPackages[@]}; do
   tallyVuln
   if ! [[ "$(dpkg -l | grep $i | grep ii)" ]]; then
      score "Unauthorized package $i removed" 3
   fi
done

for i in ${badFiles[@]}; do
   tallyVuln
   if ! [[ -f $i ]]; then
      score "Unauthorized file $i removed" 1
   fi
done

for i in ${goodFiles[@]}; do
      if ! [[ -f $i ]]; then
      score "Authorized file $i removed" -2
   fi
done

#In all of the below, you must add tallyVuln before every point to make sure\
#that each point is accounted for in the total.

tallyVuln
#In this example, we are rewarding points for a file being properly configured.
#The file is /etc/ssh/sshd_config. The option is PermitRootLogin.
#The setting is no.
if [[ "$(cat /etc/ssh/sshd_config | grep -i permitrootlogin | grep no)" ]]; then
   score "Root login disabled" 1
fi

tallyVuln
#In this example, we are rewarding points for a file existing.
if [[ -f /etc/shadow ]]; then
   score "Shadow file exists" 1
fi

tallyVuln
#In this example, we are rewarding points for a directory being removed.
if ! [[ -d /home/harry/ ]]; then
   score "/home/harry/ removed" 1
fi

tallyVuln
#In this example, we are checking that a file has the correct permissions.
#/etc/sudoers is the file and the permissions are 600
if [[ "$(stat -c %a /etc/sudoers | grep 600)" ]]; then
   score "/etc/sudoers set correctly" 2
fi

tallyVuln
#In this example, we are checking that the output of a command is correct.
if [[ "$(ufw status | grep -i 'enabled')" ]]; then
   score "Firewall enabled" 2
fi

tallyVuln
#In this example, ufw is the package that we want installed.
if [[ "$(dpkg -l | grep ufw | grep ii)" ]]; then
   score "Ufw installed" 2
fi

tallyVuln
#In this example, 4444 is the port that netcat is listening on.
#Replace this number with the port you have opened.
if ! [[ "$(netstat -tulpn | grep 4444)" ]]; then
   score "Netcat listener disabled" 2
fi

echo "<p><b><font size='7'>Score: $score</p></b></font>" > /srv/score.html
echo "<p><font size='5'>$vulns/$totalVulns</font></p>" >> /srv/score.html
cat /srv/.score.html >> /srv/score.html
cp /srv/score.html /var/www/html/score.html
