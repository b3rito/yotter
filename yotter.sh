#!/bin/bash

while getopts ":t:d:s:u" opt; do
	case $opt in
		t)
			target=$OPTARG   
		;;
		d)
			dictionary=$OPTARG   
		;;
		s)
			speed=$OPTARG 
		;;
		u)
			echo "updating..."			
			wget "https://raw.githubusercontent.com/b3rito/yotter/master/yotter.sh" -O yotter.sh
			exit 
		;;
		\?)
			echo "Invalid option: $OPTARG"
			exit
		;;
	esac
done

echo -e "\e[1;94m==========================================================================\e[m"
cat << "img"
   ____     __   ,-----.  ,---------. ,---------.    .-''-.  .-------.     
   \   \   /  /.'  .-,  '.\          \\          \ .'_ _   \ |  _ _   \    
    \  _. /  '/ ,-.|  \ _ \`--.  ,---' `--.  ,---'/ ( ` )   '| ( ' )  |    
     _( )_ .';  \  '_ /  | :  |   \       |   \  . (_ o _)  ||(_ o _) /    
 ___(_ o _)' |  _`,/ \ _/  |  :_ _:       :_ _:  |  (_,_)___|| (_,_).' __  
|   |(_,_)'  : (  '\_/ \   ;  (_I_)       (_I_)  '  \   .---.|  |\ \  |  | 
|   `-'  /    \ `"/  \  ) /  (_(=)_)     (_(=)_)  \  `-'    /|  | \ `'   / 
 \      /      '. \_/``".'    (_I_)       (_I_)    \       / |  |  \    /  
  `-..-'         '-----'      '---'       '---'     `'-..-'  ''-'   `'-'    
 because otters are cute!                                     (by b3rito)                  
img
echo -e "\e[1;94m==========================================================================\e[m"
echo -e "=========================================================================="
echo -e "version: 1.1"
echo -e "credits: b3rito"
echo -e "twitter/github: b3rito"
echo -e "report bugs: b3rito@mes3hacklab.org"
echo -e "update: ./yotter.sh -u"
echo -e "\e[1;33mUSAGE: ./yotter.sh -t example.com -d /path/to/dictionary -s 1000(threads)\e[m"
echo -e "=========================================================================="

if [ -z "$target" ]; then
	echo "insert TARGET (-t example.com)"
	exit
fi
if [ -z "$dictionary" ]; then
	echo "insert path to DICTIONARY (-d)"
	echo "I highly recomend the wordlist 'subdomains-10000.txt' from the tool dnscan provided by rbsec (https://github.com/rbsec/dnscan)"
	read -p "would you like yotter to download and use it for you? (yes/no): " dnscan
	if [ -z "$dnscan" ]; then
		echo "I did not understand"	
	elif [ "$dnscan" == "yes" ] || [ "$dnscan" == "y" ]; then
		wget https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-10000.txt
		dictionary="subdomains-10000.txt"
	elif [ "$dnscan" == "no" ] || [ "$dnscan" == "n" ]; then
		exit
	else 
		echo "I did not understand"		
		exit
	fi
fi
if [ -z "$speed" ]; then
	echo "insert THREADS (-s 1000)"
	exit
fi
if [ "$speed" -lt 1 ]; then
	echo "-.-"
	exit
fi

ip=$(host $target | head -n 1 | awk '{print $4}')
range=$(whois $ip | grep -E 'NetRange|inetnum' | awk '{print $2,$3,$4}')

#ip
echo -e "\e[1;94mthe target IP is: $ip \e[m"
#range
echo "checking if range is available"
echo -e "\e[1;94mrange: $range \e[m"

#removing old files

rm /tmp/onlineFoundSubdomains -f
rm /tmp/generatedList -f

#searching for subdomains DNS + small brute (pkey.in | hackertarget.com | virustotal.com)

echo -e "\e[0;32mSearching for stuff online...\e[m"

curl https://www.pkey.in/tools-i/search-subdomains -H 'User-Agent: Mozilla/5.0 (Mobile; rv:49.0) Gecko/49.0 Firefox/49.0' --data "zone=$target&submit=" --insecure -m 30 | grep "border-left-style: none;" | cut -d '>' -f2 | cut -d '<' -f1 | grep -F . | uniq | sed 's/\.$//' | grep "$target" > /tmp/onlineFoundSubdomains

curl http://api.hackertarget.com/hostsearch/?q=$target -m 30 | sed 's/,/ /' | awk '{print $1}' | grep "$target" >> /tmp/onlineFoundSubdomains

curl https://www.virustotal.com/en/domain/$target/information/ -H 'Host: www.virustotal.com' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -m 30 | grep information | grep "$target" | awk '{print $3}' | sed 's/\// /g' | awk '{print $4}' >> /tmp/onlineFoundSubdomains

echo -e "\e[0;32m--------------Online Found Subdomains-------------------\e[m"

onlineSub=$(cat /tmp/onlineFoundSubdomains | sort | uniq)

echo "$onlineSub"

#bruteforce for subdomains

echo -e "\e[0;32m--------------Dictionary attack start-------------------\e[m"

while read wl; do 
	generateSubList="$(echo "$wl.$target")"
	echo "$generateSubList" | grep "$target" >> /tmp/generatedList
done <"$dictionary" 

# multithread [ magic - 1600 attempts in 6 seconds ;) ]

bruteSub=$(</tmp/generatedList)
bruteSubList="$(echo "$bruteSub" | xargs -n 1 -P30 -I LINK sh -c " host 'LINK' | grep "address" | grep '$target'")" 
bruteSubListFinal="$(echo "$bruteSubList" | awk '{print $1}' | sort | uniq )"
echo "$bruteSubListFinal"
read -p "Would you like to check for new IPs (of the servers that hosts the subdomains)? (y/n): " newIp
	if [ -z "$newIp" ]; then
		echo "I did not understand"	
	elif [ "$newIp" == y ] || [ newIp == yes ]; then
		newIp="$(echo "$bruteSubListFinal"| xargs -n 1 -P30 -I NEWIP sh -c " host 'NEWIP'" | awk '{print $4}' | grep '\.')"
	elif  [ "$newIp" == n ] || [ newIp == no ]; then
		echo "Newly discovered IPs will not be analyzed"
	else 
		echo "I did not understand"		
		exit
	fi

echo "$newIp" | sort | uniq

echo -e "\e[0;32m--------------Dictionary attack done-------------------\e[m"
echo  -e "\e[1;94m---------------Results combined-------------------\e[m"

combinedLists=$(echo "$onlineSub $bruteSubList" | tr ' ' '\n' | sort -u | grep "$target")
echo "$combinedLists" | sort | uniq 

#Port Scan

echo  -e "\e[1;94m-------------------Port scan-------------------\e[m"
echo "choose what to analyze"
echo " 1) target IP: $ip"
echo " 2) set target IP manually "
echo " 3) target IP RANGE: $range"
echo " 4) target IPs discovered by subdomains:"
echo "$newIp" | sort | uniq

read -p "what would you like to analyze (1,2 or 3)?: " targetIp
if [ "$targetIp" == "1" ]; then
	echo "analyzing $ip"

#creating target + port list
	
	ipPlusPortList="$(for p in {1..65535}; do echo "$ip $p"; done)"
	
#scanning ports + multithread [ magic - scanning 65535 ports in 2 minutes ;) ]
	
	echo "----------scanning 65535 ports for WebApps----------"
	ncScan="$(echo "$ipPlusPortList" | xargs -n 1 -P $speed -I LIST sh -c "nc -zv -w 1 LIST 2>&1 | grep open | grep 'http*'")"
	validIpPortList="$(echo "$ncScan" | awk '{print $2,$3}' | cut -d '[' -f2 | sed 's/]/:/g' | sed 's/ //g')"
	echo "$validIpPortList"

elif [ "$targetIp" == "2" ]; then
	read -p "please enter target IP: " customIp
#creating target + port list
	
	ipPlusPortList="$(for p in {1..65535}; do echo "$customIp $p"; done)"
	
#scanning ports + multithread [ magic - scanning 65535 ports in 2 minutes ;) ]
	
	echo "----------scanning 65535 ports for WebApps----------"
	ncScan="$(echo "$ipPlusPortList" | xargs -n 1 -P $speed -I LIST sh -c "nc -zv -w 1 LIST 2>&1 | grep open | grep 'http*'")"
	validIpPortList="$(echo "$ncScan" | awk '{print $2,$3}' | cut -d '[' -f2 | sed 's/]/:/g' | sed 's/ //g')"
	echo "$validIpPortList"

elif [ "$targetIp" == "3" ]; then
	echo "analyzing $range"

# creating target list
	
	rangeIp="$(echo "$range" | awk '{print $1}')"	
	
# removing IP class (C)
	
	NumIniz="$(echo "$rangeIp" | grep -Po '.*(?=\.)')"
	NumMin="$(echo "$range" | awk '{print $1}' | rev | cut -d. -f1 | rev)"
	NumMax="$(echo "$range" | awk '{print $3}' | rev | cut -d. -f1 | rev)"

# target final range
	
	rangeIpFull="$(seq -f "$NumIniz.%g" $NumMin $NumMax)"
	rangeIpPlusPortList="$(for line in $(echo "$rangeIpFull"); do echo $line; for p in {1..65535}; do echo $line $p; done; done)"

#scanning for WebApps on all ports
	echo "-------------------scanning 65535 ports for WebApps-------------------"

#scanning ports + multithread [ magic - scanning 65535 ports in 2 minutes ;) ]
	
	ncScan="$(echo "$rangeIpPlusPortList" | xargs -n 1 -P $speed -I LIST sh -c "nc -zv -w 1 LIST 2>&1 | grep open | grep 'http*'")"
	validIpPortList="$(echo "$ncScan" | awk '{print $2,$3}' | cut -d '[' -f2 | sed 's/]/:/g' | sed 's/ //g')"
	echo "$validIpPortList"

elif [ "$targetIp" == "4" ]; then
	echo "analyzing..."



# target final range

	subIpPlusPortList="$(for line in $(echo "$newIp"); do echo $line; for p in {1..65535}; do echo $line $p; done; done)"

#scanning for WebApps on all ports
	echo "-------------------scanning 65535 ports for WebApps-------------------"

#scanning ports + multithread [ magic - scanning 65535 ports in 2 minutes ;) ]
	
	ncSubScan="$(echo "$subIpPlusPortList" | xargs -n 1 -P $speed -I LIST sh -c "nc -zv -w 1 LIST 2>&1 | grep open | grep 'http*'")"
	validSubIpPortList="$(echo "$ncSubScan" | awk '{print $2,$3}' | cut -d '[' -f2 | sed 's/]/:/g' | sed 's/ //g')"	
	echo "$validSubIpPortList"

else
	echo "I did not understand"
fi

#final list

echo "-------------------Final Target list-------------------"
finalCombinedLists="$(echo "$combinedLists $validIpPortList $validSubIpPortList" | tr ' ' '\n' | sort -u)"
echo "$finalCombinedLists" | sort | uniq

#run dirb 

read -p "Press Enter to run dirb..."
echo "-------------------DIRB-------------------"
file="$(echo "$finalCombinedLists")"
for url in $file; do
	xterm -e bash -c 'dirb http://'$url'/ /usr/share/dirb/wordlists/big.txt -w -f -o `echo $RANDOM.dirb.yotter % 99999`; exec bash' &
done
