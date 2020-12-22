all: cniffer
	$(info All done!)

cniffer: main.c
	gcc -o cniffer main.c -lpcap

clean:
	$(info Clean done!)
	rm data.log
