# __examples__
I have some files that I'm examining with different commands and tools. This gets kinda repetitive. There are multiple ways and multiple commands that can be used to do the same analysis.

## __ssh brute force__
```sh
# download ssh logs
➜ wget https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/SSH_2k.log -q
➜ ls
SSH_2k.log

# examining what the logs look like
➜ head SSH_2k.log 
Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!
Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
Dec 10 06:55:46 LabSZ sshd[24200]: input_userauth_request: invalid user webmaster [preauth]
Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown
Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=173.234.31.186 
Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2
Dec 10 06:55:48 LabSZ sshd[24200]: Connection closed by 173.234.31.186 [preauth]
Dec 10 07:02:47 LabSZ sshd[24203]: Connection closed by 212.47.254.145 [preauth]
Dec 10 07:07:38 LabSZ sshd[24206]: Invalid user test9 from 52.80.34.196
Dec 10 07:07:38 LabSZ sshd[24206]: input_userauth_request: invalid user test9 [preauth]

# searching for invalid user in the logs and seeing how many lines it shows up on
➜ grep 'Invalid user' SSH_2k.log | wc -l
113

# this just finds and displays 5 usernames from top of the log file that were invalid
➜ grep 'Invalid user' SSH_2k.log | cut -d' ' -f8 | head -n 5 
webmaster
test9
webmaster
chen
pgadmin

# this shows top 5 invalid user usernames
# we find all invalid user lines with grep, then select just the usernames. sort and unique finds unique usernames and counts them then we do sort based on count and show top 5 usernames
➜ grep 'Invalid user' SSH_2k.log | cut -d' ' -f8 | sort | uniq -c | sort -n -r | head -n 5 
     21 admin
      6 support
      6 oracle
      5 test
      4 user

# this shows top IPs that had invalid users 
➜ grep 'Invalid user' SSH_2k.log | cut -d' ' -f10 | sort | uniq -c | sort -n -r | head -n 5 
     35 103.99.0.122
     29 187.141.143.180
      9 183.62.140.253
      8 5.188.10.180
      7 185.190.58.151

# this shows most common username and ip combo. top ip tried admin 10 times
# cut is being used to grab username and ip
➜ grep 'Invalid user' SSH_2k.log | cut -d' ' -f8,10 | sort | uniq -c |sort -r -n |head -n 5 
     10 admin 103.99.0.122
      4 user 103.99.0.122
      4 oracle 187.141.143.180
      4 admin 5.188.10.180
      4 admin 185.190.58.151

# this is just looking for some less common usernames, specifically usernames that were used 2 times or less
# count data is passed to awk and awk is used to do filtering
➜ grep 'Invalid user' SSH_2k.log | cut -d' ' -f8 | sort | uniq -c | sort -n -r |awk '{ if($1 <= 2) print;}' |head -n 5 
      2 webmaster
      2 ubuntu
      2 ubnt
      2 magnos
      2 ftpuser

# this shows usernames that are less than or equal to 2 chars long
➜ grep 'Invalid user' SSH_2k.log | cut -d' ' -f8 | sort | uniq -c | sort -n -r |awk '{ if(length($2) <= 2) print $2;}' 
0
pi

# this shows usernames longer than 8 chars
➜ grep 'Invalid user' SSH_2k.log | cut -d' ' -f8 | sort | uniq -c | sort -n -r |awk '{ if(length($2) > 8) print $2;}' 
webmaster
anonymous
postgres1
Management

# this displays the longest username
# count is again passed into awk and then we use if then to set length of variable max
➜ grep 'Invalid user' SSH_2k.log | cut -d' ' -f8 | sort | uniq -c | sort -n -r |awk '{ if (length($2) > max) max = length($2) } END { print max }'  
10

# here, all ip's are checked against greynoise. this dataset is old so i wasn't expecting too many results
# output is saved go gnout.json. greynoise returns json back
➜ for ip in $(grep 'Invalid user' SSH_2k.log | cut -d' ' -f10 | sort | uniq |grep -v from); do curl -s https://api.greynoise.io/v3/community/$ip; done > gnout.json

# this is what the json looks like
➜ head gnout.json 
{
    "ip": "103.207.39.16",
    "noise": false,
    "riot": false,
    "message": "IP not observed scanning the internet or contained in RIOT data set."
}{
    "ip": "103.207.39.165",
    "noise": false,
    "riot": false,
    "message": "IP not observed scanning the internet or contained in RIOT data set."

# i just wanna see how many unique messages there can be. in my dataset, there are two.
➜ cat gnout.json |jq '.message' |sort | uniq
"IP not observed scanning the internet or contained in RIOT data set."
"Success"

# here im using jq to only find json object that has message set to success
➜ cat gnout.json |jq 'select(.message=="Success")'
{
  "ip": "187.141.143.180",
  "noise": true,
  "riot": false,
  "classification": "unknown",
  "name": "unknown",
  "link": "https://viz.greynoise.io/ip/187.141.143.180",
  "last_seen": "2022-01-11",
  "message": "Success"
}
```

## __network traffic__
```sh
# downloading and extracting dataset
➜ wget https://www.secrepo.com/maccdc2012/http.log.gz

➜ gunzip http.log.gz

➜ ls   
http.log

# looking at the logs to see what they look like.
# tab is missing because of the way i copied and pasted my output. these logs are in tsv format
➜ head http.log 
1331901000.000000CHEt7z3AzG4gyCNgci192.168.202.7950465192.168.229.251801HEAD192.168.229.251/DEASLog02.nsf-Mozilla/5.0 (compatible; Nmap Scriptin
g Engine; http://nmap.org/book/nse.html)00404Not Found---(empty)-------
1331901000.010000CKnDAp2ohlvN6rpiXl192.168.202.7950467192.168.229.251801HEAD192.168.229.251/DEASLog03.nsf-Mozilla/5.0 (compatible; Nmap Scriptin
g Engine; http://nmap.org/book/nse.html)00404Not Found---(empty)-------
1331901000.030000CNTrjn42F3LB58MZH6192.168.202.7950469192.168.229.251801HEAD192.168.229.251/DEASLog04.nsf-Mozilla/5.0 (compatible; Nmap Scriptin
g Engine; http://nmap.org/book/nse.html)00404Not Found---(empty)-------
1331901000.040000C1D7mK1PlzKEnEyG03192.168.202.7950471192.168.229.251801HEAD192.168.229.251/DEASLog05.nsf-Mozilla/5.0 (compatible; Nmap Scriptin
g Engine; http://nmap.org/book/nse.html)00404Not Found---(empty)-------
1331901000.050000CGF1bVMyl9ALKI32l192.168.202.7950473192.168.229.251801HEAD192.168.229.251/DEASLog.nsf-Mozilla/5.0 (compatible; Nmap Scriptin
g Engine; http://nmap.org/book/nse.html)00404Not Found---(empty)-------
1331901000.070000CQ7uZu2HtGNngGZl5c192.168.202.7950475192.168.229.251801HEAD192.168.229.251/decsadm.nsf-Mozilla/5.0 (compatible; Nmap Scriptin
g Engine; http://nmap.org/book/nse.html)00404Not Found---(empty)-------
1331901000.080000COdckp4ZoGPteMJ2E4192.168.202.7950477192.168.229.251801HEAD192.168.229.251/decslog.nsf-Mozilla/5.0 (compatible; Nmap Scriptin
g Engine; http://nmap.org/book/nse.html)00404Not Found---(empty)-------
1331901000.090000CzhIEIizmxUoN6gP7192.168.202.7950479192.168.229.251801HEAD192.168.229.251/DEESAdmin.nsf-Mozilla/5.0 (compatible; Nmap Scriptin
g Engine; http://nmap.org/book/nse.html)00404Not Found---(empty)-------
1331901000.110000CkzNrm1sDTsMMEeh9k192.168.202.7950481192.168.229.251801HEAD192.168.229.251/dirassist.nsf-Mozilla/5.0 (compatible; Nmap Scriptin
g Engine; http://nmap.org/book/nse.html)00404Not Found---(empty)-------
1331901000.120000CyOt6C4vWuJE2n5pDb192.168.202.7950483192.168.229.251801HEAD192.168.229.251/doladmin.nsf-Mozilla/5.0 (compatible; Nmap Scriptin
g Engine; http://nmap.org/book/nse.html)00404Not Found---(empty)-------

# counting the lines in this file. there are a ton of events
➜ wc -l http.log 
2048442 http.log

# this is one way to use cut with tab
➜ head http.log|cut -d$'\t' -f1
1331901000.000000
1331901000.010000
1331901000.030000
1331901000.040000
1331901000.050000
1331901000.070000
1331901000.080000
1331901000.090000
1331901000.110000
1331901000.120000

# another way to use cut with tab. here i pressed control+v then pressed the tab key
➜ head http.log|cut -d'    ' -f1
1331901000.000000
1331901000.010000
1331901000.030000
1331901000.040000
1331901000.050000
1331901000.070000
1331901000.080000
1331901000.090000
1331901000.110000
1331901000.120000

# top destination ip's
➜ cut -d$'\t' -f5 http.log| sort | uniq -c | sort -rn |head
1310095 192.168.229.101
 225936 192.168.25.203
  53229 192.168.23.202
  42018 192.168.26.202
  36476 192.168.24.202
  34261 192.168.27.203
  32977 192.168.24.101
  31879 192.168.28.202
  20736 192.168.27.253
  20646 192.168.27.102

# top source ip's
➜ cut -d$'\t' -f3 http.log| sort | uniq -c | sort -rn |head 
1289498 192.168.203.63
 232259 192.168.202.79
 212234 192.168.202.102
 169126 192.168.202.110
  47379 192.168.202.138
  28332 192.168.202.140
  14032 192.168.202.118
  10487 192.168.202.96
   8794 192.168.202.125
   6214 192.168.202.65

# i'm only looking for ip's that had nmap as the user-agent
# this shows source ip's that had nmap as the user-agent
➜ grep "Nmap Scripting" http.log| cut -d$'\t' -f3 |sort |uniq -c |sort -rn
   8165 192.168.202.79
    939 192.168.204.45
    749 192.168.202.108
    197 192.168.202.140
    111 192.168.202.144
    100 2001:dbb:c18:202:20c:29ff:fe41:4be7
     86 2001:dbb:c18:202:20c:29ff:fe93:571e
     77 192.168.203.45
     67 192.168.202.136
     49 192.168.202.4
     44 192.168.202.100
     31 192.168.203.61
     14 192.168.202.141

# here i'm looking for status code 404. -F can be used with awk to specify seperator
# awk finds status code 404 then prints source ip and uri.
# sort and unique find unique IP and url uri combo.
# i select the ip with cut then i do unique w/ count and find top 5 source IPs
➜ awk -F'\t'  '{ if($15==404) print $3,$10 }' http.log |sort |uniq |cut -d' ' -f1 |uniq -c | sort -rn |head -n 5
1267726 192.168.203.63
 207807 192.168.202.79
  26113 192.168.202.110
  14294 192.168.202.102
  11205 192.168.202.118

# here i just find unique user-agents and their count
# dirbuster obviously has a high count
➜ awk -F'\t' '{print $12}' http.log  |sort |uniq -c | sort -rn |head
1289244 DirBuster-0.12 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
 236626 Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)
 203846 Mozilla/5.0 SF/2.03b
  90826 Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)
  89004 Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)
  71345 -
  10629 Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)
   7230 Mozilla/5.0 (X11; Linux i686; rv:10.0.2) Gecko/20100101 Firefox/10.0.2
   6480 Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko/20100101 Firefox/11.0
   5680 Mozilla/5.0 (X11; Linux i686 on x86_64; rv:10.0.2) Gecko/20100101 Firefox/10.0.2

# this is looking for status code of 200 AND uri including the word shell, matched lines are printed
# i take 5 lines and only print src ip, dst ip, dst port, method, hostname, and uri
# finally, i use tr to replace tab with a comma
➜ awk -F'\t' '{ if(($15==200) && ($10 ~ /shell/) ) print ;}' http.log | head -n 5 |cut -d$'\t' -f3,5,6,8-10 |tr '\t' ','
192.168.202.110,192.168.27.202,80,GET,192.168.27.202,/main/inc/c99shell.php
192.168.202.110,192.168.27.202,80,GET,192.168.27.202,/chat/c99shell.php
192.168.202.110,192.168.27.202,80,GET,192.168.27.202,/stylesheet/c99shell.php
192.168.202.110,192.168.27.202,80,GET,192.168.27.202,/reports/c99shell.php
192.168.202.110,192.168.27.202,80,GET,192.168.27.202,/dump/c99shell.php
```

## __suricata json logs__
```sh
# downloading a suricata alert log file (typically eve.json but only the alerts)
➜ wget https://raw.githubusercontent.com/FrankHassanabad/suricata-sample-data/master/samples/wrccdc-2018/alerts-only.json

# exploring the file content
➜ head alerts-only.json 
[
  {
    "timestamp": "2018-03-24T14:37:19.037299-0600",
    "flow_id": 928532049924531,
    "pcap_cnt": 169577,
    "event_type": "alert",
    "src_ip": "0.0.0.0",
    "src_port": 26078,
    "dest_ip": "10.47.8.150",
    "dest_port": 22,

# just printing the first event
➜ jq '.[0]' alerts-only.json   
{
  "timestamp": "2018-03-24T14:37:19.037299-0600",
  "flow_id": 928532049924531,
  "pcap_cnt": 169577,
  "event_type": "alert",
  "src_ip": "0.0.0.0",
  "src_port": 26078,
  "dest_ip": "10.47.8.150",
  "dest_port": 22,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2001219,
    "rev": 20,
    "signature": "ET SCAN Potential SSH Scan",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "flow": {
    "pkts_toserver": 1,
    "pkts_toclient": 0,
    "bytes_toserver": 74,
    "bytes_toclient": 0,
    "start": "2018-03-24T14:37:19.037299-0600"
  }
}

# printing specifically the alert data for the first event
➜ jq '.[0].alert' alerts-only.json  
{
  "action": "allowed",
  "gid": 1,
  "signature_id": 2001219,
  "rev": 20,
  "signature": "ET SCAN Potential SSH Scan",
  "category": "Attempted Information Leak",
  "severity": 2
}

# keys lets you print just the keys. this shows keys an event and alert part of the event
➜ jq '.[0] | keys' alerts-only.json 
[
  "alert",
  "dest_ip",
  "dest_port",
  "event_type",
  "flow",
  "flow_id",
  "pcap_cnt",
  "proto",
  "src_ip",
  "src_port",
  "timestamp"
]
➜ jq '.[0] | .alert | keys' alerts-only.json 
[
  "action",
  "category",
  "gid",
  "rev",
  "severity",
  "signature",
  "signature_id"
]

# here i'm looking for all signature names then sorting and counting them to find top 5 alerts
➜ jq '.[] | .alert.signature' alerts-only.json | sort |uniq -c | sort -rn |head -n 5
      2 "ET EXPLOIT Serialized Java Object Calling Common Collection Function"
      1 "SURICATA TLS overflow heartbeat encountered, possible exploit attempt (heartbleed)"
      1 "SURICATA TLS invalid record/traffic"
      1 "SURICATA TLS invalid record version"
      1 "SURICATA TLS invalid handshake message"

# here im selecting signatures containing MALWARE then only printing signature, dest ip, and source ip in csv format
➜ jq '.[] | select(.alert.signature|match("MALWARE")) | [.alert.signature, .dest_ip, .src_ip] | @csv' alerts-only.json
"\"ET MALWARE Spyware Related User-Agent (UtilMind HTTPGet)\",\"64.135.77.30\",\"10.47.42.68\""
"\"ET MALWARE Lavasoft PUA/Adware Client Install\",\"104.17.60.19\",\"10.47.1.155\""

# i'm filtering by a specific source ip then printing all the alert signatures and dest ip's for it
➜ jq '.[] | select(.src_ip=="10.47.42.68") | [.alert.signature, .dest_ip, .src_ip]' alerts-only.json 
[
  "ET MALWARE Spyware Related User-Agent (UtilMind HTTPGet)",
  "64.135.77.30",
  "10.47.42.68"
]
[
  "ET POLICY AOL Toolbar User-Agent (AOLToolbar)",
  "66.235.134.197",
  "10.47.42.68"
]
[
  "ET TROJAN Suspicious Malformed Double Accept Header",
  "64.135.77.30",
  "10.47.42.68"
]
```

## __jq custom print line__
```sh
# printing formatted line with jq
# input
# {"names": [ {"first":"jason", "last": "doe" }, {"first":"jane", "last": "doe" } ] }
➜ jq '.names[] | ("First name is " + .first + " last name is " + .last )'
"First name is jason last name is doe"
"First name is jane last name is doe"
```

