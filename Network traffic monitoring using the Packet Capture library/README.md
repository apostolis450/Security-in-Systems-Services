# Network traffic monitoring tool
###  
Author : Zacharopoulos Apostolos  
Date   : 15/11/2020
##
![C](https://img.shields.io/static/v1?label=&message=%20&color=00599C&style=flat-square&logo=C&logoColor=white)<br>
**Instructions**:  
* Compile:  
   ```make```  
* Run:  
   ```./nwmonitor -i **[device_name]**``` <em>(for me it was ethernet device with name enp9s0)  </em> (keyboard interrupt required to terminate)
   ```./nwmonitor -r **[filename]** ```  <em>(I used the given "test_pcap_5mins.pcap" file) </em>
  
**Details**<br>
The purpose of this project is to monitor the network traffic over a device or a given file with traffic captured. The tool captures only packets over ethernet protocol, separates them based on IP version (4/6), and unpacking more details such as protocol (tcp/udp), header/payload length etc..