#include "PktFowrd.h"

int main( int argc , char ** argv )
{
	char ch ;
	int flag = 0 ;
	
	if( argc > 1 )
	{
		//opterr = 0 ;
		while((ch = getopt(argc,argv,"r:t:f:i:c:vh*"))!= -1)
		{
			switch(ch)
			{
			case 'v':
			case 'V':
				ShowVersion("1.0");
				return 0 ;
				break ;
			case 'h':
			case 'H':
				ShowHelp( argv[0] ) ;
				return 0 ;
				break ;
			case 't':
				strcpy(outInterface , optarg ) ;
				flag |= 1<<0 ;
				break ;
			case 'i':
				strcpy(inInterface , optarg ) ;
				flag |= 1<<1 ;
				break ;
			case 'r':
				strcpy(pcapFile , optarg);
				flag |= 1<<2 ;
				break ;
			case 'f':
				strcpy(filterStr,optarg);
				break ;
			case 'c':
				maxCount = atoi((char*)optarg) ;
				break ;
			}
		}
		if( optopt != 0 ) flag = 0 ;
	}
	
	
	if( flag == 3 )
	{
		PktFowrdInterface() ;
	}
	else if( flag == 5 )
	{
		PktFowrdFile() ;
	}
	else
	{
		ShowHelp( argv[0] ) ;
		return 0 ;
	}
	

	return 0;
}

void err_sys(const char *errmsg)
{
        perror(errmsg);
        exit(1);
}

void ShowVersion( char * version )
{
        printf("ReleaseVersion: %s \n",version );
        printf("The Proprietor: WAZ \n");
        printf("Last Make Time: %s %s \n" , __DATE__ , __TIME__ );
}

void ShowHelp( char * pro_name)
{
	printf("Usage: %s [-v] [-h] \n",pro_name);
	printf("Usage: %s -r PcapFile -t outInterface [-f filter] [-c maxCount] \n",pro_name);
	printf("Usage: %s -i inInterface -t outInterface [-f filter] [-c maxCount] \n",pro_name);
}

void PktFowrdFile()
{	
	printf("[INFO] PcapFile: %s , OutInterface: %s , Filter: \"%s\" , maxCount: %d !\n" , pcapFile , outInterface , filterStr , maxCount ) ;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net_ip;
	bpf_u_int32 net_mask;
	struct bpf_program fcode;
	
	struct pcap_pkthdr *m_headerPtr;
	const u_char *m_dataPtr ;

	pcap_t* descr;
	const u_char *packet;

	
	if ((adhandle = pcap_open_offline(pcapFile,errbuf)) == NULL)
	{
		err_sys("Can't open cap file");
	}
	

	pcap_lookupnet(outInterface,&net_ip,&net_mask,errbuf);
	
	if (pcap_compile(adhandle, &fcode , filterStr , 1, net_mask) < 0)
	{
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(adhandle));exit(1);
	}

	if(pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(adhandle));exit(1);
	}


	descr = pcap_open_live(outInterface,BUFSIZ,1,-1,errbuf);
	if(descr == NULL)
	{
		printf("pcap_open_live(): %s\n",errbuf);
		return ;
	}
	
	int pcapIndex = 0 ;
	
	while(pcap_next_ex(adhandle, &m_headerPtr, &m_dataPtr)>0)
	{
		pcap_sendpacket(descr, m_dataPtr , m_headerPtr->caplen ) ;
		pcapIndex++ ;
		printf("==> %d \n" , pcapIndex ) ;
		if( maxCount > 0 && pcapIndex == maxCount ) break ;
		
	}
	
}

void PktFowrdInterface()
{
	printf("[INFO] InInterface: %s , OutInterface: %s , Filter: \"%s\" , maxCount: %d !\n" , inInterface , outInterface , filterStr , maxCount ) ;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net_ip;
	bpf_u_int32 net_mask;
	struct bpf_program fcode;
	
	struct pcap_pkthdr *m_headerPtr;
	const u_char *m_dataPtr ;

	pcap_t* descr;
	

	int timeout = -1;
	int snaplen = BUFSIZ ;
	int promisc = 1 ;
	if((adhandle= pcap_open_live(inInterface,snaplen, promisc, timeout, errbuf)) == NULL)
	{
		printf("adhandle pcap_open_live(): %s\n",errbuf);
		return ;
	}

	pcap_lookupnet(inInterface,&net_ip,&net_mask,errbuf);
	
	if (pcap_compile(adhandle, &fcode , filterStr , 1, net_mask) < 0)
	{
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(adhandle));exit(1);
	}

	if(pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(adhandle));exit(1);
	}
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "pcap_datalink: %s\n", pcap_geterr(adhandle));exit(1);
	}


	descr = pcap_open_live(outInterface,BUFSIZ,1,-1,errbuf);
	if(descr == NULL)
	{
		printf("descr pcap_open_live(): %s\n",errbuf);
		return ;
	}
	
	int pcapIndex = 0 ;
	
	while(1)
	{
		while( pcap_next_ex(adhandle, &m_headerPtr, &m_dataPtr) == 0 ) ;
		pcap_sendpacket(descr, m_dataPtr , m_headerPtr->caplen ) ;
		pcapIndex++ ;
		printf("==> %d \n" , pcapIndex ) ;
		if( maxCount > 0 && pcapIndex == maxCount ) break ;
	}
	
}

