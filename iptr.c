#include <pcap.h>
#include <pcap-bpf.h>
#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#define FILTER "tcp"                                    /* capture TCP package */
#define NOOPTIMIZE 0
#define OPTIMIZE   1

void capture_packet(int datalink, pcap_t *pd, struct bpf_program fcode);
char *next_pcap(int *len, pcap_t *pd);
void err_sys(const char *errmsg);

int main( int argc , char ** argv )
{
        char *device = "eth1";                          /* network device */
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *pd;                                     /* device descriptor */
        int snaplen = 200, promisc =0, timeout = 500;   /* 500ms */
        bpf_u_int32 netp, maskp;                        /* network address and mask address */
        struct bpf_program fcode;
        int datalink;

        if ((device = pcap_lookupdev(errbuf)) == NULL)
                err_sys(errbuf);
	if( argc  != 2 ) 
	{
		printf("Usage: %s ETH\n",argv[0]) ;
		return 1 ;
	}
	strcpy(device,argv[1]); // test device
        printf("device: %s\n", device);
        pd = pcap_open_live(device, snaplen, promisc, timeout, errbuf);
        if (pd == NULL)
                err_sys(errbuf);

/*
        if (pcap_lookupnet(device, &netp, &maskp, errbuf) == -1)
                err_sys(errbuf);
        else {                                          * output network and mask address *
                char net[INET_ADDRSTRLEN], mask[INET_ADDRSTRLEN];

                if (inet_ntop(AF_INET, &netp, net, sizeof(net)) == NULL)
                        err_sys("inet_ntop");
                else if (inet_ntop(AF_INET, &maskp, mask, sizeof(net)) == NULL)
                        err_sys("inet_ntop");
                printf("net: %s, mask: %s\n", net, mask);
        }
*/
        if (pcap_compile(pd, &fcode, FILTER, NOOPTIMIZE, maskp) == -1) {
                fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(pd));
                exit(1);
        }
        if (pcap_setfilter(pd, &fcode) == -1) {
                fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(pd));
                exit(1);
        }
        if ((datalink = pcap_datalink(pd)) == -1) {
                fprintf(stderr, "pcap_datalink: %s\n", pcap_geterr(pd));
                exit(1);
        }
        printf("datalink = %d\n", datalink);

        capture_packet(datalink, pd, fcode);

        exit(0);
}

void capture_packet(int datalink, pcap_t *pd, struct bpf_program fcode)
{
    int len , i ;
    char *ptr;
    struct ip *ip;
 /*   struct ether_header *eptr;   */
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

    for ( i = 0 ; i < 100 ; i++ ) {
        ptr = next_pcap(&len, pd);

        switch (datalink) {
            case DLT_NULL:
                ptr += 4;
                break;
            case DLT_EN10MB:
                ptr += 14;
                break;
            case DLT_SLIP:
                ptr += 24;
                break;
            case DLT_PPP:
                ptr += 5;
                break;
        }

        /** .......IP.. **/
        ip = (struct ip *) ptr;
        printf("src ip: %s <===> dst ip: %s\n",
                inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src)),
                inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst)));


    }
}

#if 0

struct pcap_pkthdr {
        struct timeval ts;      /* time stamp */
        bpf_u_int32 caplen;     /* length of portion present */
        bpf_u_int32 len;        /* length this packet (off wire) */
};

#endif

char *next_pcap(int *len, pcap_t *pd)
{
    char *ptr;
    struct pcap_pkthdr hdr;

    while ((ptr = (char *) pcap_next(pd, &hdr)) == NULL);
    *len = hdr.caplen;

    return(ptr);
}

void err_sys(const char *errmsg)
{
        perror(errmsg);
        exit(1);
}

 
