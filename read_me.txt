Issue:
Brute force login attack to ASA Anyconnect

What does script do?
This script recevies AAA login failure syslog from ASA, if reaches threshlold, it requests ASA to shun attacker's IP.

Script is listening on UDP/6789
Script will prompt to ask for username, password and secret which are used to ssh into ASA.
Script will prompt to ask for failure threshold


ASA needs be configured with the following syslog setting:

logging list FAILED-AUTH level warnings class webvpn
logging list FAILED-AUTH message 113005
logging list FAILED-AUTH message 113015
logging trap FAILED-AUTH
logging host inside x.x.x.x 17/6789