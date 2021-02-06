#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct file_list          flist;
typedef struct entry              entry_type;
typedef struct modification_list  mdlist;
typedef struct modifiers          mods;

//this list holds files user tried to access without permission.
typedef struct file_list
{
	char *fname;
	struct file_list *next;

} flist;

typedef struct entry {

	int uid ; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char *date; /* file access date */
	char *time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	struct  entry *next ;
	flist *nextfile;

} entry_type;


typedef struct modification_list
{
	char *uid;
	char *hash;
	char *access_type;
	mdlist *next;
} mdlist;

typedef struct modifiers
{
	char *uid;
	int times;
	mods *next;
} mods;


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{

	//Creating a linked list for every user to log his unauth actions
	
	entry_type *head = NULL;
	head = (entry_type *)malloc(sizeof(entry_type));
	if (head == NULL)
	{	
		printf("Failed to initialize list\n");
		return ;
	}
	//head->uid=; //first empty list's head
	head->next=NULL;
	//array with head addr of every user's list
	size_t *users = (size_t *)malloc(sizeof(size_t));
	users[0]=(size_t)head; //store head's address

	char *log_line = NULL;
	size_t len = 0;
	ssize_t read;
	int lines=0;
	int k=0; //counter for user's array
	while (read = getline(&log_line,&len,log) != -1)
	{
		int i=0;
		char *line[7];
		entry_type *current = (entry_type*)users[0]; //head of user[0]
		//printf("head addr %ld\n",(size_t)current);
		char * token = strtok(log_line,"\t");
		
		while(token != NULL){
			line[i] = malloc(strlen(token)*sizeof(char));
			strcpy(line[i],token);
			token = strtok(NULL,"\t");
			i++;
		}
		if (k == 0 && !current->uid) //no entries yet
		{	
			current->uid = atoi(line[0]);
			current->file = line[1];
			current->date = line[2];
			current->time = line[3];
			current->access_type = atoi(line[4]);
			current->action_denied = atoi(line[5]);	
			current->fingerprint = line[6];
			current->next = NULL;
			current->nextfile = NULL;
			//this will be accessed if the firstmost log is malicious
			if ( current->action_denied == 1 ) //access with no permission -> record it
			{
				flist *flist_head = (flist *)malloc(sizeof(flist));
				flist_head->fname = malloc(sizeof(char)*strlen(line[1]));
				strcpy(flist_head->fname,line[1]);
				current->nextfile=flist_head;
			}
			
		}else {
			for (int x = 0; x <= k; x++)
			{
				int exist = 0;
				entry_type *curr = (entry_type*)users[x];
		
				if ( curr->uid == atoi(line[0]) ) // if line's uid is one of already recorder
				{	
					if ( atoi(line[5]) == 1 ) //access with no permission -> record it
					{
						if (curr->nextfile != NULL)//user has list with unauth files
						{
							flist *flnode = curr->nextfile; //take the head
							while (flnode->next != NULL)
							{
								//go to the last node
								flnode = flnode->next;
							}
							flist *new_flnode = (flist *)malloc(sizeof(flist));
							new_flnode->fname = malloc(sizeof(char)*strlen(line[1]));
							strcpy(new_flnode->fname,line[1]);
							flnode->next=new_flnode;
							new_flnode->next=NULL;
						}else	//users hasn't unauth file_list;
						{	
							flist *flist_head = (flist *)malloc(sizeof(flist));
							flist_head->fname = malloc(sizeof(char)*strlen(line[1]));
							strcpy(flist_head->fname,line[1]);
							curr->nextfile=flist_head;
						}
					}

					while (curr->next != NULL) //go to end of user's list,add new node
					{
						curr = curr->next;
					}

					entry_type *new_node = (entry_type *)malloc(sizeof(entry_type));

					new_node->uid = atoi(line[0]);
					new_node->file = line[1];
					new_node->date = line[2];
					new_node->time = line[3];
					new_node->access_type = atoi(line[4]);
					new_node->action_denied = atoi(line[5]);
					new_node->fingerprint = line[6]; 
					new_node->next = NULL;
					curr->next = new_node;
					exist=1;
					//break;
				}else if (exist==0 && x==k) //last iteration and not found uid
				{				//add new user and give him new list
					entry_type *new_node = (entry_type *)malloc(sizeof(entry_type));
					users[k+1] = (size_t)new_node; //new head of new user's list
					new_node->uid = atoi(line[0]);
					new_node->file = line[1];
					new_node->date = line[2];
					new_node->time = line[3];
					new_node->access_type = atoi(line[4]);
					new_node->action_denied = atoi(line[5]);
					new_node->fingerprint = line[6]; 
					new_node->next = NULL;
					if ( atoi(line[5]) == 1 ) //access with no permission -> record it
					{
						flist *flist_head = (flist *)malloc(sizeof(flist));
						flist_head->fname = malloc(sizeof(char)*strlen(line[1]));
						strcpy(flist_head->fname,line[1]);
						new_node->nextfile=flist_head;
						flist_head->next=NULL;
					}
					k++; // # of distinct users
				}
				
			}
		}
		
	}
	printf("Malicious users:\n");
	for (int i = 0; i <= k; i++)
	{
		int malicious = 0;
		entry_type *curr = (entry_type *)users[i];
		
		if (curr->nextfile != NULL)// = user tried malicious actions
		{
			flist *flnode = curr->nextfile; //head of the file list -> itterate
			while (flnode != NULL)
			{
				malicious++;
				flnode=flnode->next;
			}
		}
		if (malicious >= 7)
		{
			printf("User -> | uid = %d |\n",curr->uid);
		}
	}
	return;
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
	mdlist *head = (mdlist*)malloc(sizeof(mdlist));
	if (head == NULL)
	{	
		printf("Failed to initialize list\n");
		return ;
	}
	head->next=NULL;

	mods *hd = (mods*)malloc(sizeof(mods));
	if (hd == NULL)
	{	
		printf("Failed to initialize list\n");
		return ;
	}
	hd->next=NULL;
	hd->times=0;

	char *log_line = NULL;
	size_t len = 0;
	ssize_t read;

	while (read = getline(&log_line,&len,log) != -1)
	{
		int i=0;		//split each line word by word
		char *line[7];
		char * token = strtok(log_line,"\t");
		mdlist *current = head;
		while(token != NULL){
			line[i] = malloc(strlen(token)*sizeof(char));
			strcpy(line[i],token);
			token = strtok(NULL,"\t");
			i++;
		}				//if given filename found in log file
		if ( (strcmp(file_to_scan,line[1]) == 0 ) && (atoi(line[5]) != 1) && (atoi(line[4]) != 0)) 
		{	//if condition (file=file given && hasPermission to access && write mode)
			if(!current->uid) //empty list -> current = head
			{
				current->uid = (char *)malloc(sizeof(char)*strlen(line[0]));
				strcpy(current->uid,line[0]);
				current->hash = (char *)malloc(sizeof(char)*strlen(line[6]));
				strcpy(current->hash,line[6]);
				current->access_type = (char *)malloc(sizeof(char)*strlen(line[4]));
				strcpy(current->access_type,line[4]);
				//printf("modif added %s %s\n",current->uid,current->hash);
			}else
			{
				while (current->next!=NULL)
				{
					current=current->next;
				}
				mdlist *new_node = (mdlist*)malloc(sizeof(mdlist));
				new_node->uid = (char *)malloc(sizeof(char)*strlen(line[0]));
				strcpy(new_node->uid,line[0]);
				new_node->hash = (char *)malloc(sizeof(char)*strlen(line[6]));
				strcpy(new_node->hash,line[6]);
				new_node->access_type = (char *)malloc(sizeof(char)*strlen(line[4]));
				strcpy(new_node->access_type,line[4]);
				current->next = new_node;
				new_node->next = NULL;
				//printf("modif added %s %s\n",new_node->uid,new_node->hash);
			}
		}	
	}

	mdlist *current = head;
	mods   *curr    = hd; //this new list helps to record times each user modified a file
	
	curr->uid=(char*)malloc(sizeof(char)*strlen(current->uid));
	strcpy(curr->uid,current->uid); //set first user with first found uid, arbitrarily
	//counting every user's modification
	while (current->next != NULL) // till (last-1) node of list
	{
		curr=hd;
		if (strcmp(current->hash,current->next->hash) != 0) //hash changed = file modified
		{	
			while (curr != NULL)
			{		//look if modifier's uid exists, increase timesAccessed
				if (strcmp(current->next->uid,curr->uid)==0)
				{
					curr->times += 1;
					break;
				}
					//else create a node for each unique uid
				else if (curr->next==NULL && (strcmp(current->next->uid,curr->uid)!=0))
				{
					mods *new = (mods*)malloc(sizeof(mods));
					new->uid=(char*)malloc(sizeof(char)*strlen(current->next->uid));
					strcpy(new->uid,current->next->uid);
					new->times = 1;
					new->next = NULL;
					curr->next = new;
					break;
				}
				curr=curr->next;
			}
		}
		current=current->next;
	}
	mods   *node    = hd;
	while (node != NULL)
	{
		printf("uid: %s\t# of file modifications: %d\n",node->uid,node->times);
		node = node->next;
	}
	
	return;

}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}
	
	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
