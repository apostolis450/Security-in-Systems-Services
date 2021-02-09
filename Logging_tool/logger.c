#define _GNU_SOURCE
#define LOG_DATA_LENGTH 512

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <errno.h>
#include <fcntl.h>

void actionsLogger(FILE *fd,const char * path,int permission,int accessType);

FILE *
fopen(const char *path, const char *mode) 
{
	int accessType;
	int fileExist;
	int hasPerm = 0; //zero means not denied (default)

	if( access( path, F_OK ) != -1 ) 
		fileExist = 0; // zero = exists 
	else 
		fileExist = 1; //doesn't exist
	/********************************************************/
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	/********************************************************/
	
	FILE *mylogger = (*original_fopen)(path,mode);
	//if user doesn't have perm set the perm variable for logging
	if (mylogger == NULL){
        printf("Failed to open the file: %s\n",path);
		if (errno == EACCES || errno == EPERM){
            //printf("You dont have the permission.\n");
        	hasPerm = 1;
		}
	}
	// log if file created
	if( (access( path, F_OK ) != -1) && fileExist == 1 ) //file created
		actionsLogger(mylogger,path,hasPerm,0); //log creation
	
	accessType = 1; //read mode

	actionsLogger(mylogger,path,hasPerm,accessType);
	
	if(mylogger != NULL)
		close(fileno(mylogger));

	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	//int fileExist=0;
	int hasPerm = 0; //zero means not denied (default)
	//EXTRACTING THE FILENAME FROM THE FILE STREAM
	int MAXSIZE = 255;
    char proclnk[MAXSIZE];
    char filename[MAXSIZE];
	int fno = fileno(stream);
    sprintf(proclnk, "/proc/self/fd/%d", fno);
    size_t r = readlink(proclnk, filename, MAXSIZE);
	filename[r] = '\0';

	// if( access( basename(filename), F_OK ) != -1 )  
	// 	fileExist = 1; //doesn't exist
	/********************************************************/
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	/********************************************************/
	//mylogger will get the returned nmemb. zero means failed
	//size_t mylogger = (*original_fwrite)(ptr, size, nmemb, stream);
	if(size == 0 && nmemb == 0){ //nothing to write,file remains same
		//close(mylogger);
		actionsLogger(stream,basename(filename),hasPerm,2);
		return original_fwrite_ret;
	}else if (original_fwrite_ret < nmemb) //means fwrite failed
	{
		printf("Failed to write the file: %s\n",basename(filename));
		if (errno == EACCES || errno == EPERM){
            printf("You dont have the permission.\n");
        	hasPerm = 1;
		}
	}

	//close(mylogger);
	actionsLogger(stream,basename(filename),hasPerm,2);

	return original_fwrite_ret;
}


void actionsLogger(FILE *fd,const char * path,int permission,int accessType){
	
	char final_log[LOG_DATA_LENGTH];
	char date[15];
	char timestamp[15];
	char userID[5];
	char usrHasPermission[2];
	char usrAccessType[2];
	MD5_CTX ctx; 
	unsigned char digest[MD5_DIGEST_LENGTH];
	
	sprintf(usrHasPermission,"%d",permission);
	sprintf(usrAccessType,"%d",accessType);

	//user id
	uid_t uid = getuid();
	sprintf(userID,"%d",uid);
	//date and timestamp
	time_t t = time(&t);
	struct tm * info = localtime(&t);

	strftime(date,sizeof(date),"%x",info);                    //MM/DD/YY format
	strftime(timestamp,sizeof(timestamp),"%H:%M:%S%p",info);  //HH:MM:SS (AM-PM)

	//open log file -- giving owner read/write permission because open creates the file without permisions
	int fl = open("file_logging.log", O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);
	if (fl == -1)
	{
		printf("Failed to open file_logging.log\n");
		return;
	}
	
	if (fd == NULL) //can't access the file thus can't create hash
	{	
		// setting hash to zero cause we dont have access to file content
		//creating log pattern
		sprintf(final_log,"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",userID,path,date,timestamp,usrAccessType,usrHasPermission,"0");

		//write log to log_file
		write(fl,final_log,strlen(final_log));
	}
	else
	{
		// count file size (bytes)
		fseek(fd, 0L, SEEK_END);
		size_t file_size = ftell(fd);
		fseek(fd, 0L, SEEK_SET);

		//read file content for hash creation
		char file_content[file_size];
		fread(file_content,file_size,1,fd);

		//create the hash
		MD5_Init(&ctx);
		MD5_Update(&ctx,file_content,sizeof(file_content));
		MD5_Final(digest,&ctx);
		//turn hash into string (hex representation)
		char md5FinalString[MD5_DIGEST_LENGTH*2 + 1];
		for(int i = 0; i < MD5_DIGEST_LENGTH; ++i)
    		sprintf(&md5FinalString[i*2], "%02x", (unsigned int)digest[i]);

		//creating log pattern
		sprintf(final_log,"%s\t%s\t%s\t%s\t%s\t%s\t%s\n",userID,path,date,timestamp,usrAccessType,usrHasPermission,md5FinalString);

		//write log to log file
		write(fl,final_log,strlen(final_log));
	}

	close(fl);
}