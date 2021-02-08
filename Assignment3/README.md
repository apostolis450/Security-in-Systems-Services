# Implementing a basic ransomware
###  
Author : Zacharopoulos Apostolos  
Date   : 3/12/2020
##  Instructions    
**make**  
-----compile all 

**make ransom args='-help'**            
-----Prints out help about available commands for script.

**make ransom args='-e encr'**           
-----encrypt everything in directory encr  dir already exists).

**make ransom args='-e'**  
-----creates some dummy files in pwd,encrypt them  and removes the originals.

**make ransom args='-p encr -c 10'**  
-----Create 10 dummyfiles in directory encr. (given dir has to exist)

**make monitor args='-v 8'**  
-----Reads the log file and prints to the console  the number of files created by ransomware during  
the last 20 minutes.Given number is the lower limit. i.e. It will print out if files created are more than 8.

**make monitor args='-e'**  
-----Reads the log file and prints out to console all files that got encrypted by the ransomware.    
## Details.
1. **Part1**  
The _ransomware.sh_ bash script serves two functionalities,encryption of files  
that exist in the same folder and encryption of files inside a given a directory.  
This project integrates the previous one, so I added a bypass for fopen64 as well  
which is used by openssl lib. The functionality of creating a bunch of dummy files in a directory uses the **ransom_support.c** .  
Every action is logged by the logger from the previous assignment.  
2. **Part2**  
Finally, new functionalities added in the log monitor tool from the previous  
project,(**acmonitor.c**) so it logs and detects the encryptions that ransomware does.
