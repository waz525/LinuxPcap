defualt : iptr getinfo test speed_pcap sendpcap alldev

iptr : 	iptr.c
	gcc iptr.c -lpcap -o iptr 

getinfo : getinfo.c
	gcc getinfo.c -lpcap -o getinfo

test : test.c 
	gcc test.c -lpcap -o test

speed_pcap : speed_pcap.c
	gcc speed_pcap.c -lpcap -lpthread -o speed_pcap

sendpcap: sendpcap.c
	gcc sendpcap.c -lpcap -o sendpcap

alldev: alldev.c
	gcc alldev.c -lpcap -o alldev

clean :
	rm -f iptr getinfo test speed_pcap alldev sendpcap
