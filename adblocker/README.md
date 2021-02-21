# Adblock
###  
Author : Zacharopoulos Apostolos  
Date   : 18/12/2020
##
**Details**
This tool uses as input a text file '*domainNames.txt*' with domains you would like to block, finds their ip using  ```dig +short``` command and creates iptables rules for these ips. <br>
**Instructions**:   
*Run (as root):*
  * ./adblock.sh -[mode] <br>     
  * modes: <br>
    <ul>
        <li><em>domains</em></li>
        <li><em>ips</em></li>
        <li><em>save</em></li>
        <li><em>load</em></li>
        <li><em>reset</em></li>
        <li><em>list</em></li>
        <li><em>help</em></li>
    <ul><br>  

