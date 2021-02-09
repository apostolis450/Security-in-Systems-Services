#include <stdio.h>
#include <string.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {
			"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"
			};


	/* example source code */

	for (i = 0; i < 5; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}

	file = fopen("file_0","w");
	if (file == NULL){
		printf("fopen error \n");
		return 1;
	}
	char message[16] = "This is a test";
	bytes = fwrite(message, strlen(message), 1, file);
	fclose(file);
	
	// only super user has permission for this file (test)
	// This test creates the conditions to test the malicious user printing
	// for the monitor
	for (int i = 0; i < 7; i++)
	{
		file = fopen("test","w");
		if (file == NULL){
			//printf("fopen error. \n");
			continue;
		}
		char mess[16] = "This is a test";
		bytes = fwrite(mess, strlen(mess), 1, file);
		fclose(file);
	}
	
	
}
