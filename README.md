# yotter
This bash script performs recon by:
1) finding the targets IP
2) finding the targets IP range
3) checks online for subdomains ( pkey.in | hackertarget.com | virustotal.com )
4) bruteforces for subdomains ( around 250 checks per second )
5) port scans all found IPs for HTTP* services ( around 500 ports per second )

and then uses dirb do discover directories that might lead to information leakage (such as credentials found in server-status)

# Requirements
netcat > https://en.wikipedia.org/wiki/Netcat

dirb > http://dirb.sourceforge.net/

# Author
Written by b3rito at mes3hacklab

# Installation
    chmod +x yotter.sh

# Usage
    b3rito@antani:~/yotter $ ./yotter.sh 
    ==========================================================================
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
    ==========================================================================
    ==========================================================================
    version: 1.0
    credits: b3rito
    twitter/github: b3rito
    report bugs: b3rito@mes3hacklab.org
    update: ./yotter.sh -u
    USAGE: ./yotter.sh -t example.com -d /path/to/dictionary 
    ==========================================================================
