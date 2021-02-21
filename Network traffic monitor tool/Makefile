all: nwmonitor 

nwmonitor: nwmonitor.c 
	gcc -Wall nwmonitor.c -o nwmonitor -lpcap

monitor :
	./nwmonitor -i enp9s0

clean:
	rm -f nwmonitor

