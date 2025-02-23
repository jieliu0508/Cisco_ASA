Issue:
Dod/DDoS Brute force authentication attack to ASA Anyconnect

What does script do?
This script recevies AAA login failure syslog from ASA, if reaches threshlold, it requests ASA to shun attacker's IP.

Script will prompt to ask for syslog UDP port to listen on
Script will prompt to ask for ASA username and password, this user has privilege 15 
Script will prompt to ask for failure threshold


ASA needs be configured with the following syslog setting (UDP/514):

logging list FAILED-AUTH level warnings class webvpn
logging list FAILED-AUTH message 113005
logging list FAILED-AUTH message 113015
logging trap FAILED-AUTH
logging host inside x.x.x.x 17/514