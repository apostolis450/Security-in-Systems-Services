#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdbool.h>
#include "simple_crypto.h"

void one_time_pad()
{
    char plaintext[MAX_INPUT_LENGTH];
    printf("[OTP] input: ");
    fgets(plaintext,MAX_INPUT_LENGTH,stdin);
    //Create the random key - Read random bytes from /dev/urandom  
    unsigned char buffer[strlen(plaintext)];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {printf("Failed to open /dev/urandom file"); return 1;}
    read(fd, buffer, strlen(plaintext));
    close(fd);
    
    unsigned char temp;
    char encrypted_message[strlen(plaintext)];
    char decrypted_message[strlen(plaintext)];
    //encryption - XOR-ing
    for (int i = 0; i < strlen(plaintext); i++)
    {
        temp = plaintext[i] ^ buffer[i];
        encrypted_message[i] = temp;
    }
    printf("[OTP] encrypted: 0x%02x\n",encrypted_message);
    //decryption - XOR-ing
    for (int i = 0; i < strlen(plaintext); i++)
    {
        temp = encrypted_message[i] ^ buffer[i];
        decrypted_message[i] = temp;
    }
    printf("[OTP] decrypted: %s",decrypted_message);
    return;
}

void caesars_cipher(){
    int key = 0;
    char plaintext[MAX_INPUT_LENGTH];
    strcpy(plaintext,"");
    //read plaintext
    printf("[Caesars] input: ");
    fgets(plaintext,MAX_INPUT_LENGTH,stdin);
    //read shifting key
    printf("[Caesars] key: ");
    scanf("%d",&key);
    
    unsigned char encrypted_message[strlen(plaintext)];
    unsigned char decrypted_message[strlen(plaintext)];
    //key must be a positive number
    bool isPositive = key >= 0 ? true : false;

    int totalLetters = 'Z' - 'A'; //same for lowercase
    int totalNumbers = '9' - '0'; 
    int i = 0 ;
    // ENCRYPTION
    if(isPositive){
        for (i = 0; i < strlen(plaintext); i++){
            if(isdigit(plaintext[i])){ 
                if((plaintext[i] + key ) > '9'){
                    int shiftsLeft = (plaintext[i] + key) - '9';
                    if(shiftsLeft >= 2 * totalLetters + 2){ 
                        //pass uppers-lowers and goes back to nums
                        shiftsLeft %= 52 ; //26+26 shifts
                        if (shiftsLeft == 0 )
                        {
                            encrypted_message[i] = '0'; //complete cycle
                            continue;
                        }
                        if (shiftsLeft <= totalNumbers){ //returned to numbers area
                            encrypted_message[i] = ('0' - 1) + shiftsLeft;
                        }else if (shiftsLeft <= totalLetters){
                            encrypted_message[i]=('A' - 1) + shiftsLeft;
                        }
                        else if (shiftsLeft > totalLetters){
                            //goes to lowercase
                            
                            shiftsLeft -= totalLetters; //passed 25 uppercased
                            encrypted_message[i]=('a' - 1) + shiftsLeft;
                         }
                    }
                    else if (shiftsLeft <= totalLetters)
                    {
                        encrypted_message[i] = ('A' - 1) + shiftsLeft;
                    }
                    else
                    {
                        shiftsLeft -= totalLetters; //passed 25 uppercased
                        encrypted_message[i]=('a' - 1) + shiftsLeft;
                    }
                    
                }
                else
                {   
                    //printf("else cond\n");
                    encrypted_message[i] = plaintext[i] + key;
                }
                
            }
            else if(isupper(plaintext[i])){
                if (plaintext[i] + key > 'Z'){
                    int shiftsLeft = (plaintext[i] + key) - 'Z';
                    if(shiftsLeft >= totalNumbers + totalLetters + 2){ 
                        //lowers-nums and comes back to uppers
                        shiftsLeft %= 36 ; //26+10 shifts
                        if (shiftsLeft == 0 )
                        {
                            encrypted_message[i] = 'A'; //complete cycle
                            continue;
                        }
                        if (shiftsLeft <= totalLetters){ //returned to uppers area
                            encrypted_message[i] = ('A' - 1) + shiftsLeft;
                        }else if (shiftsLeft > totalLetters){
                            encrypted_message[i]=('a' - 1) + shiftsLeft;
                        }
                        else if (shiftsLeft > totalLetters*2){
                            //goes to numbers
                            shiftsLeft -= totalLetters; //passed 25 uppercased
                            encrypted_message[i]=('0' - 1) + shiftsLeft;
                         }
                    }
                    else if (shiftsLeft <= totalLetters)
                    {
                        
                        encrypted_message[i] = ('a' - 1) + shiftsLeft;
                    }
                    else
                    {
                        shiftsLeft -= totalLetters+1; //passed 25 uppercased : need 26 shifts
                        encrypted_message[i]=('0' - 1) + shiftsLeft;
                    }
                }
                else
                {   
                    //printf("else cond\n");
                    encrypted_message[i] = plaintext[i] + key;
                }
            }
            else if(islower(plaintext[i])){
                if (plaintext[i] + key > 'z'){
                    int shiftsLeft = (plaintext[i] + key) - 'z';
                    if(shiftsLeft >= totalNumbers + totalLetters + 2){ 
                        //lowers-nums and comes back to uppers
                        shiftsLeft %= 36 ; //26+10 shifts
                        if (shiftsLeft == 0 )
                        {
                            encrypted_message[i] = 'a'; //complete cycle
                            continue;
                        }
                        if (shiftsLeft <= totalLetters){ //returned to uppers area
                            encrypted_message[i] = ('a' - 1) + shiftsLeft;
                        }else if (shiftsLeft > totalLetters){
                            encrypted_message[i]=('0' - 1) + shiftsLeft;
                        }
                        else if (shiftsLeft > totalLetters*2){
                            shiftsLeft -= totalLetters; //passed 25 uppercased
                            encrypted_message[i]=('0' - 1) + shiftsLeft;
                         }
                    }
                    else if (shiftsLeft <= totalNumbers)
                    {
                        
                        encrypted_message[i] = ('0' - 1) + shiftsLeft;
                    }
                    else
                    {
                        shiftsLeft -= totalNumbers+1; //passed numbers: 9 nums 10 shifts to pass them
                        encrypted_message[i]=('A' - 1) + shiftsLeft;
                    }
                }
                else
                {   
                    encrypted_message[i] = plaintext[i] + key;
                }
            }
            else{
                encrypted_message[i]=' ';
                continue; //skip specials..
            }           
        }
        encrypted_message[i] = '\0';
    }
    else {
        printf("Shifting key must be a positive number!\n");
        return 1;
    }
    printf("[Caesars] encrypted: %s\n",encrypted_message);
    /******************************************************************
     * ***************************************************************
    *******************************************************************/
    //                              DECRYPTION
    for (i = 0; i < strlen(encrypted_message); i++){
            if(isdigit(encrypted_message[i])){ 
                if((encrypted_message[i] - key ) < '0'){
                    int shiftsLeft = key - (encrypted_message[i] - '0');
                    if(shiftsLeft >= 2 * totalLetters + 2){ 
                        shiftsLeft %= 52 ; //26+26 shifts
                        if (shiftsLeft == 0 )
                        {
                            decrypted_message[i] = '9'; //complete cycle
                            continue;
                        }
                        if (shiftsLeft <= totalNumbers){ //returned to numbers area
                            decrypted_message[i] = ('9' + 1) - shiftsLeft;
                        }else if (shiftsLeft <= totalLetters){
                            decrypted_message[i]=('z' + 1) - shiftsLeft;
                        }
                        else if (shiftsLeft > totalLetters){
                            //goes to uppercase
                            shiftsLeft -= (totalLetters+1); 
                            decrypted_message[i]=('Z' + 1) - shiftsLeft;
                         }
                    }
                    else if (shiftsLeft <= totalLetters)
                    {
                        decrypted_message[i] = ('z' + 1) - shiftsLeft;
                    }
                    else
                    {
                        shiftsLeft -= totalLetters+1; //passed 25 uppercased
                        decrypted_message[i]=('Z' + 1) - shiftsLeft;
                    }
                    
                }
                else
                {   
                    decrypted_message[i] = encrypted_message[i] - key;
                }
                
            }
            else if(isupper(encrypted_message[i])){
                if ((encrypted_message[i] - key ) < 'A') {
                    int shiftsLeft = key - (encrypted_message[i] - 'A');
                    if(shiftsLeft >= totalNumbers + totalLetters + 2){ 
                        //lowers-nums and comes back to uppers
                        shiftsLeft %= 36 ; //26+10 shifts
                        if (shiftsLeft == 0 )
                        {
                            encrypted_message[i] = 'Z'; //complete cycle
                            continue;
                        }
                        if (shiftsLeft <= totalLetters){ //returned to uppers area
                            encrypted_message[i] = ('Z' + 1) - shiftsLeft;
                        }else if (shiftsLeft > totalLetters){
                            encrypted_message[i]=('9' + 1) - shiftsLeft;
                        }
                        else if (shiftsLeft > totalLetters*2){
                            //goes to numbers
                            shiftsLeft -= totalLetters; 
                            encrypted_message[i]=('z' - 1) + shiftsLeft;
                         }
                    }
                    else if (shiftsLeft <= totalNumbers)
                    {
                        decrypted_message[i] = ('9' + 1) - shiftsLeft;
                    }
                    else
                    {
                        shiftsLeft -= totalNumbers+1; 
                        decrypted_message[i]=('z' + 1) - shiftsLeft;
                    }
                }
                else
                {   
                    decrypted_message[i] = encrypted_message[i] - key;
                }
            }
            else if(islower(encrypted_message[i])){
                if (encrypted_message[i] - key < 'a'){
                    int shiftsLeft = key - (encrypted_message[i] - 'a');
                    if(shiftsLeft >= totalNumbers + totalLetters + 2){ 
                        //lowers-nums and comes back to uppers
                        shiftsLeft %= 36 ; //26+10 shifts
                        if (shiftsLeft == 0 )
                        {
                            decrypted_message[i] = '0'; //complete cycle
                            continue;
                        }
                        if (shiftsLeft <= totalLetters){ //returned to lowers area
                            decrypted_message[i] = ('z' + 1) - shiftsLeft;
                        }else if (shiftsLeft > totalLetters){
                            decrypted_message[i]=('Z' + 1) + shiftsLeft;
                        }
                        else if (shiftsLeft > totalLetters*2){
                            shiftsLeft -= totalLetters; //passed 25 uppercased
                            decrypted_message[i]=('9' + 1) - shiftsLeft;
                         }
                    }
                    else if (shiftsLeft <= totalLetters)
                    {
                        decrypted_message[i] = ('Z' + 1) - shiftsLeft;
                    }
                    else
                    {
                        shiftsLeft -= totalLetters+1; //passed uppers: 
                        decrypted_message[i]=('9' + 1) - shiftsLeft;
                    }
                }
                else
                {   
                    decrypted_message[i] = encrypted_message[i] - key;
                }
            }
            else{
                decrypted_message[i]=' ';
                continue; //skip specials..
            }           
        }
        decrypted_message[i] = '\0';
        printf("[Caesars] decrypted: %s\n",decrypted_message);
    }
   