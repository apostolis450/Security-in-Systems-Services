/*
*   This program supports a functionality of the ransomware script.
*   Creates a given number of files in a given directory
*   using fopen(),which we modified such that we can log every action.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void main(int argc, char const *argv[])
{
    FILE* file;
    char *pattern = "%s/dummyfile%d";
    char filename[20];
    
    for (int i = 0; i < atoi(argv[2]); i++) {
       
        sprintf(filename,pattern,argv[1],i);
        
		file = fopen(filename, "w");
		if (file == NULL) 
			printf("fopen error\n");
        fclose(file);

        memset(filename,0,20);
	}
    
    return ;
}





