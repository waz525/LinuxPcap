#include "CatchPcap.h"

int main( int argc , char ** argv )
{
	strcpy( dev,"eth1");
	strcpy( filter , "" ) ;
	strcpy( capfile , "down.cap" );
	count = 0 ;
	wFlag = 0 ;
	promisc = 0 ;
	detil = 0 ;
	snaplen = 68 ;
	if( argc > 1 )
	{
		int ch;
		opterr = 0;
		while((ch = getopt(argc,argv,"i:f:w:c:r:s:pxvVhH*"))!= -1)
		{
			switch(ch)
			{
			case 'v':
			case 'V':
				ShowVersion("1.1");
				return 0 ;
				break ;
			case 'h':
			case 'H':
				ShowHelp( argv[0] ) ;
				return 0 ;
				break ;
			case 'i':
				strcpy(dev,optarg);
				break ;
			case 'f':
				strcpy(filter , optarg);
				break ;
			case 'w':
				wFlag = 1 ;
				strcpy(capfile , optarg);
				break ;
			case 'c':
				count=atoi(optarg) ;
				break ;
			case 's':
				snaplen=atoi(optarg) ;
				break ;
			case 'p':
				promisc = 1 ;
				break ;
			case 'x':
				detil = 1 ;
				break ;
			case 'r':
				wFlag = -1 ;
				strcpy(capfile , optarg);
				break ;
			default:
				printf("Error: NOT OPTION %s !!!\n",ch);
				return 0 ;
			}
		}

	}
	else
	{
		ShowHelp( argv[0] ) ;
		return 0;
	}

	if( wFlag == -1 )
	{
		printf("INFO: read capfile is %s " , capfile ) ;
	}
	else
	{
		printf("INFO: interface is %s ",dev);
		if( wFlag == 1 ) printf("; write capfile is %s " , capfile ) ;
		if( promisc == 1 ) printf("; set interface promisc ") ;
	}
	if( count > 0 ) printf("; count is %d " , count ) ;
	if( strlen(filter) > 0 ) printf("; filter is \"%s\" " , filter ); 
	printf("...\n") ;
	if( wFlag == -1 ) ReadFromFile() ;
	else CatchPacket() ;
	return 0 ;
}

void err_sys(const char *errmsg)
{
        perror(errmsg);
        exit(1);
}

void ShowVersion( char * version )
{
        printf("ReleaseVersion : %s \n",version );
        printf("The Proprietor : WAZ \n");
        printf("Last Make Time : %s %s \n" , __DATE__ , __TIME__ );
}

void ShowHelp( char * pro_name)
{
        printf("Usage: %s [-v] [-h] \n",pro_name);
        printf("Usage: %s [-i interface] [-f FILTER] [-c count] [-w file] [-s snaplen] [-x] [-p]\n",pro_name);
        printf("Usage: %s [-r file] [-f FILTER] [-c count] [-w file]  [-x]\n",pro_name);
        printf("options : \n");
        printf("        -v : show version \n");
        printf("        -h : show help \n");
        printf("        -i interface : set catch packets from which interface (used only for catch) \n");
        printf("        -f FILTER : set filter expression \n");
        printf("        -c count : set catch packet's count \n");
        printf("        -w file : set file name which to write packets (used only for catch) \n");
        printf("        -r file : set file name which to read packets (used only for read) \n");
        printf("        -x : Print  each packet in hex \n");
        printf("        -p : set interface promisc mode (used only for catch) \n");
        printf("        -s : set snaplen for catch packet , default 68 (used only for catch) \n");
}

void CatchPacket() 
{
	int index = 0 ;
	unsigned long res ;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 net_ip;
	bpf_u_int32 net_mask;
	struct bpf_program fcode;
	pcap_dumper_t *dumpfile;
	int timeout = 500;
	
	struct pcap_pkthdr *m_headerPtr;
	const u_char *m_dataPtr ;
		
	if((adhandle= pcap_open_live(dev,snaplen, promisc, timeout, errbuf)) == NULL)
	{
		err_sys(errbuf);
	}

	pcap_lookupnet(dev, &net_ip, &net_mask, errbuf);
	if( wFlag == 1 )
	{
		dumpfile=pcap_dump_open(adhandle,capfile);
		if(dumpfile==NULL)
		{
			err_sys("Can't open cap file");
		}
	}

	if (pcap_compile(adhandle, &fcode,filter , 1, net_mask) < 0)
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

	printf("INFO: Begin to get pcap ... \n") ;
	while(1)
	{
		while( pcap_next_ex(adhandle,&m_headerPtr,&m_dataPtr) == 0 ) ;
		if( wFlag == 1 ) pcap_dump((u_char*)dumpfile , m_headerPtr, m_dataPtr) ;
		AnalysePacket(m_headerPtr,m_dataPtr) ;
		if( count>0 )
		{
			index++ ;
			if( index == count ) break ;
		}
	}
	
}
void ReadFromFile()
{
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	struct pcap_pkthdr *m_headerPtr;
	const u_char *m_dataPtr ;
	

	if ((adhandle = pcap_open_offline(capfile,errbuf)) == NULL)
	{
		err_sys("Can't open cap file");
	}
	
	bpf_u_int32 net_ip;
	bpf_u_int32 net_mask;
	struct bpf_program fcode;
	pcap_lookupnet(dev, &net_ip, &net_mask, errbuf);
	
	if (pcap_compile(adhandle, &fcode,filter , 1, net_mask) < 0)
	{
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(adhandle));exit(1);
	}

	if(pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(adhandle));exit(1);
	}

	int index = 0 ;
	while(pcap_next_ex(adhandle, &m_headerPtr, &m_dataPtr)>0)
	{
		AnalysePacket(m_headerPtr,m_dataPtr) ;
		if( count>0 )
		{
			index++ ;
			if( index == count ) break ;
		}
	}
}
void AnalysePacket( struct pcap_pkthdr *m_headerPtr , const u_char *m_dataPtr ) 
{
	char str[50] ;
	struct tm * t1 ;
	t1 = localtime( &m_headerPtr->ts.tv_sec) ;
	
	//time
	sprintf(str,"%.2d:%.2d:%.2d.%06ld ",t1->tm_hour, t1->tm_min, t1->tm_sec,m_headerPtr->ts.tv_usec);
	printf( str ) ;
	//src mac
	HexToMAC( m_dataPtr+6 , str);
	printf( str ) ;
	//dst mac
	HexToMAC( m_dataPtr , str);
	printf( " > %s, " , str ) ;
	//ether type
	switch( HexToLong( m_dataPtr+12 , 2 ) )
	{
	case ETHERTYPE_PUP:
		printf("ethertype PUP (0x0200), length %d: ",m_headerPtr->len ) ;
		break ;
		
	case ETHERTYPE_IP:
		printf("ethertype IPv4 (0x0800), length %d: ",m_headerPtr->len ) ;
		//src ip
		HexToIP( m_dataPtr+26 , str ) ;
		printf( "IP %s.%d " , str , HexToLong(m_dataPtr+34 , 2 )) ;
		//dst ip
		HexToIP( m_dataPtr+30 , str ) ;
		printf( "> %s.%d " , str ,HexToLong(m_dataPtr+36 , 2 )) ;
		break ;
		
	case ETHERTYPE_ARP:
		printf("ethertype ARP (0x0806), length %d: ",m_headerPtr->len ) ;
		break ;
		
	case ETHERTYPE_REVARP:
		printf("ethertype REVARP (0x8035), length %d: ",m_headerPtr->len ) ;
		break ;
		
	defualt:
		printf("%s, length %d: ",str ,m_headerPtr->len ) ;		
	}
	
	

	printf("\n");
	if( detil == 1 ) ShowPacketDetil( m_dataPtr ,m_headerPtr->caplen ) ;
}


void ShowPacketDetil(const u_char * data , int len )
{
	int ind = 0 ;
	int i ,t , m ;
	char temp1[50] ;
	char temp2[20] ;

	for( i = 0 , t=0  , m = 0 ; i < len ; i++)
	{
		
		t += HexToString(data[i] , temp1+t ) ;
		if( (t+1)%5==0 )temp1[t++] = ' ' ;
		m += HexToChar(data[i] , temp2+m ) ;
	
		if( (i+1) % 16 == 0 )
		{
			temp2[m] = '\0' ;
			printf( "\t0x%03x0:   %s  %s\n" , ind , temp1 , temp2 ) ;
			ind++ ;
			t = 0 ; m = 0 ;
		}
	}
	printf( "\t0x%03x0:   %s  ", ind, temp1 ,t ) ;
	while( t>0 && t<40) { printf(" ") ; t++ ;}
	printf("%s\n",temp2);
	printf("\n\n");
	
}

void HexToString(const unsigned char * hexChar , int length , char * newString )
{
	int i = 0 ;
	for( i = 0 ; i < length ; i+=2 )
	{
		sprintf(newString+i,"%02x", hexChar[i] ) ;
	}
	newString[i] = '\0' ;
	for( i = 0 ; i < length ; i++ )
	{
		newString[i] = toupper(newString[i]) ;
	}
	
}

int HexToString(const unsigned char hexChar , char * newString )
{
	
	sprintf(newString,"%02x ", hexChar ) ;
//	newString[0] = toupper(newString[0]) ;
//	newString[1] = toupper(newString[1]) ;
	newString[2] = '\0' ;
	return 2 ;
	
}

int HexToChar(const unsigned char hexChar , char * newchar )
{
		if( hexChar < 32 || hexChar > 126)
		{
			newchar[0] = '.';
		}
		else
		{
			sprintf( newchar ,"%c" ,  hexChar) ;
		}
		newchar[1] = '\0' ;
		return 1 ;
}

void HexToMAC(const unsigned char * hexChar , char * newString )
{
	int m = 0 ;
	for( int i = 0 ; i < 6 ; i++ )
	{
		m += HexToString( hexChar[i] , newString+m) ;
		if(i!=5) newString[m++]=':' ;
	}
	newString[m]='\0' ;
}

void HexToIP(const unsigned char * hexChar , char * newString )
{
	sprintf( newString , "%d.%d.%d.%d\0", HexToLong( hexChar , 1 ) ,HexToLong( hexChar+1 , 1 ) ,HexToLong( hexChar+2 , 1 ) ,HexToLong( hexChar+3 , 1 ) ) ;	
	
}


long HexToLong( const unsigned char * hexChar , int len )
{
	long res=0 ;
	for( int i = 0 ; i<len ; i++)
	{
		res *= 256 ;
		res += hexChar[i] ;
	}
	return res ;
}
