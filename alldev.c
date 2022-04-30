#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>/* GIMME a libpcap plz! */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int main()
{
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i=0;
    char errbuf[PCAP_ERRBUF_SIZE];
     
  	char *net;/* dot notation of the network address */  
  	char *mask;/* dot notation of the network mask    */  
	  int ret;   /* return code */  
	  bpf_u_int32 netp; /* ip          */  
	  bpf_u_int32 maskp;/* subnet mask */  
  	struct in_addr addr;  /* ask pcap to find a valid device for use to sniff on */ 
  	struct pcap_addr *p ; 
  	struct in_addr * add ;

    /* Retrieve the device list */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    /* Print the list */
    for(d=alldevs;d;d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else printf(" (No description available)\n");
	      if(d->addresses)
	      {
	      	p=d->addresses ;
	      	while( p )
	      	{
	      		if( p->addr->sa_family == AF_INET )
	      		{
	      			printf("\tIP: %s\n",p->addr->sa_data);
	      		}
	      		p = p->next ;  
	      	}
	      }
        ret = pcap_lookupnet(d->name,&netp,&maskp,errbuf); 
        if(ret == -1)  
        {   
            printf("\t%s\n",errbuf);   
            continue ;
	      }
	      addr.s_addr = netp;  
        net = inet_ntoa(addr);  
	      if(net == NULL)/* thanks Scott :-P */  
	      {    
            perror("inet_ntoa");    
            continue ;
        }  
        printf("\tNET: %s\n",net);  
	
        /* do the same as above for the device's mask */  
        addr.s_addr = maskp;  
        mask = inet_ntoa(addr);    
        if(mask == NULL)  
        {   
            perror("inet_ntoa");    
            continue ;
        }    
        printf("\tMASK: %s\n",mask);  
        
    }

    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    return(0);
}

