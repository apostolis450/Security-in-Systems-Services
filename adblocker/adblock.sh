#!/bin/bash
# You are NOT allowed to change the files' names!
#-------------------------------------------------------------
#                AUTHOR : Zacharopoulos Apostolos            #
#                Date   : 18 Dec, 2020                       #
#-------------------------------------------------------------
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    
    if [ "$1" = "-domains"  ]; then
    	#temporary file for resolved ips
    	if [ -f "tempfile.txt" ]; then
            rm -f tempfile.txt
        fi
    	touch tempfile.txt
        
        cat "$domainNames" | while read line; do
  			dig +short "$line" | while read ips; 
  			do 
  				if [[ $ips =~ [a-zA-Z] ]]; then
  					dig +short $ips | while read ip; do echo $ip >> tempfile.txt; done; 
  				else
  					echo $ips >> tempfile.txt
  				fi
  			done;  
		done 
		cat tempfile.txt | while read lines; 
		do
			iptables -A OUTPUT -d $lines -j REJECT 
		done;
		
		rm -f tempfile.txt
       	exit 0
    
    elif [ "$1" = "-ips"  ]; then
        cat IPAddresses.txt | while read line; do
			iptables -A OUTPUT -d $line -j REJECT
		done
       	exit 0
        
    elif [ "$1" = "-save"  ]; then
        iptables-save > adblockRules
        exit 0
        
    elif [ "$1" = "-load"  ]; then
        iptables-restore < adblockRules
        printf "Load completed!\n"
        exit 0
        
    elif [ "$1" = "-reset"  ]; then
        iptables -P INPUT ACCEPT 
        iptables -P OUTPUT ACCEPT
        iptables -P FORWARD ACCEPT
        iptables -Z 
        iptables -F 
        iptables -X
        printf "Reset completed!\n"
        exit 0
    elif [ "$1" = "-list"  ]; then
        iptables -S
        exit 0
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ips\t\t  Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0