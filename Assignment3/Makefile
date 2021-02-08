all: logger acmonitor test_aclog ransom_support

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

ransom_support : ransom_support.c
	gcc ransom_support.c -o ransom_support

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

ransom: logger.so ransom_support
	LD_PRELOAD=./logger.so ./ransomware.sh $(args)

monitor : acmonitor
	./acmonitor $(args)

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -rf ransom_support
	rm -rf file_*

