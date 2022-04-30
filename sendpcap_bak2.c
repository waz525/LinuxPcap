#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>


u_char pcap[]={\
0x00,0x00,0x00,0x00,0x00,0x01,0x10,0x4c,0x00,0x00,0x6d,0x8a,0x08,0x00,0x45,0x00,\
0x00,0xab,0x8e,0xb1,0x40,0x00,0x7b,0x06,0x43,0xe2,0x71,0x7a,0x34,0x74,0xb4,0x99,\
0xd2,0x31,0x0f,0x9c,0x00,0x50,0x92,0x20,0x26,0x65,0x88,0x92,0x77,0xf4,0x50,0x18,\
0xff,0xff,0x33,0x81,0x00,0x00,0x75,0x49,0x64,0x3d,0x31,0x34,0x31,0x30,0x36,0x35,\
0x35,0x34,0x36,0x35,0x26,0x70,0x61,0x73,0x74,0x75,0x72,0x65,0x4b,0x65,0x79,0x3d,\
0x32,0x66,0x33,0x32,0x31,0x31,0x65,0x36,0x33,0x30,0x61,0x38,0x66,0x30,0x63,0x31,\
0x37,0x65,0x34,0x39,0x34,0x38,0x66,0x62,0x62,0x39,0x30,0x34,0x34,0x61,0x34,0x66,\
0x31,0x31,0x38,0x30,0x38,0x38,0x31,0x65,0x26,0x66,0x61,0x72,0x6d,0x4b,0x65,0x79,\
0x3d,0x6e,0x75,0x6c,0x6c,0x26,0x66,0x6c,0x61,0x67,0x3d,0x31,0x26,0x75,0x49,0x64,\
0x78,0x3d,0x37,0x39,0x32,0x34,0x34,0x34,0x32,0x37,0x34,0x26,0x6e,0x65,0x77,0x69,\
0x74,0x65,0x6d,0x3d,0x32,0x26,0x66,0x61,0x72,0x6d,0x54,0x69,0x6d,0x65,0x3d,0x31,\
0x33,0x32,0x39,0x37,0x32,0x37,0x35,0x33,0x37\
} ;



int main(int argc,char **argv)
{
	int i;
	int rst ;char buf[1024] ;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr;     /* pcap.h                    */
	struct ether_header *eptr;  /* net/ethernet.h            */
	struct bpf_program fp;      /* hold compiled program     */
	bpf_u_int32 maskp;          /* subnet mask               */
	bpf_u_int32 netp;           /* ip                        */
	
	//dev = pcap_lookupdev(errbuf);
	//if(dev == NULL){ fprintf(stderr,"%s\n",errbuf); exit(1); }
	if( argc  != 2 )
	{
		printf("Usage: %s ETH\n",argv[0]) ;
		return 1 ;
	}
	dev = argv[1];
	printf("Info: Send from %s ... \n",dev);
	
	/* ask pcap for the network address and mask of the device */
	pcap_lookupnet(dev,&netp,&maskp,errbuf);
	/* open device for reading this time lets set it in promiscuous */
	/* mode so we can monitor traffic to another machine */
	descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
	if(descr == NULL)
	{
		printf("pcap_open_live(): %s\n",errbuf);
		exit(1);
	}
	/* Lets try and compile the program.. non-optimized */
	if(pcap_compile(descr,&fp,"host 130.0.0",0,netp) == -1)
	{
		fprintf(stderr,"Error calling pcap_compile\n");
		exit(1);	
	}	
	/* set the compiled program as the filter */
	if(pcap_setfilter(descr,&fp) == -1)
	{
		fprintf(stderr,"Error setting filter\n");
		exit(1);
	}
	
	for(i = 0; i< 10; ++i)
	{
		rst=pcap_sendpacket(descr, pcap , sizeof(pcap)) ;
		sprintf(buf,"%d",rst);
		printf("---> send: %s\n",buf) ;
	}
	
	return 0 ;
}
