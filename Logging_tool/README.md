# User activity log tool
###
Author : Zacharopoulos Apostolos  
Date   : 15/11/2020
##
1.  For the first part of this assignment I had to interfere in **fopen** function
so I can collect the requested data._logger.so_ library is created and we preload  it to achieve our goal.  **actionsLogger** function serves the
functionality of keeping the record and write it into logfile.
Data collected:  **userID, date & time of action, users permissions (using errno.h lib)**
Same thing for everyone calling the fwrite function.
Additionaly, we also read the content of the file and create the md5 hash of it and finally write all the info into file_logging.log.  

2. For the second part I created two tools, one is for printing malicious user's info and the second for printing info of every user that edited a file.  
A malicious user is described as the one that tried to access a file without having permission to do so.  
You can see that for these tools I used singly linked lists.
##  More detail:  
**acmonitor.c:**  
Implements the monitoring tools .  
**logger.c**  
This is where fopen and fwrite are bypassed and logs are created.  
**test_aclog.c**  
This file contains some testing.<br>
**Run**  
1.  
   ```make run```  
2.  
   ```make monitor```
