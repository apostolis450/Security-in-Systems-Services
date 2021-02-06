# Systems&Services_Security
##### [Projects for the purposes of this course (fall semester 2020-2021) ]
###
In this assignment I had to implement a simple cryptographic library that provides
implementation for the following cryptographic algorithms.
Folder should contain 4 files. 
1. simple_crypto.h header file which contains functions declaration of the library 
2. simple_crypto.c which contains the implementation of these functions
3. demo.c which contains the main function and make the calls to the library functions
4. Makefile
*   simple_crypto.h
Macro MAX_INPUT_LENGTH is an arbitrary number user for char array initialization.
*   simple_crypto.c :
- One-time pad.
This cipher takes an input from the user storing it in a char array, reads some random bytes from the /dev/urandom 
file and store them in a character array as well,making a key.
It reads as many bytes as the input is.
Then it iterates through each cell  XOR-ing each random byte with the corresponding
byte of the input and the result is stored in another char array. The produced string
(or just the character) is the encrypted text.XOR-ing again the encrypted text
with the key will give us the decrypted text.
- Caesars cipher.
This cipher asks the user for an input,a text to be encrypted and a key.
The key is a positive integer number and it is the times of shifting we'll apply
on each character/number of the input.Our alphabet consists of 0-9A-Za-z and I 
did the calculations based on ascii table,skipping any special character.
Example:    input char = '8' and key = 5
Ascii of digit '8' = 56. Adding 5 to 56 equals 61.However 61 corresponds to an 
unwanted special character. So, I count to the last digit character which is 9,
asciiOf('9') - asciiOf('8') = 1, 5-1 = 4. The rest 4 shifts start from char 'A'.
So the correct result = 'D'. If the shifts overpass the uppercase characters,
I continue to lowercase chars.I also used the modulo whenever it was useful.
Thats because when we have for example 10 characters,
choosing a key of 11 equals a key of 1 (11mod10=1). 
