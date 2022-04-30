#include "ParseTCP.h"

int main( int argc , char ** argv )
{
	int ch ;
	int flag = 0 ;
	if( argc > 1 )
	{
		while((ch = getopt(argc,argv,"r:vVhH*"))!= -1)
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
			case 'r':
				strcpy(pcapFile , optarg);
				flag |= 1<<0 ;
				break ;
			}
		}
	}
	
	
		
	if( flag != 1 ) 
	{
		ShowHelp( argv[0] ) ;
		return 0 ;
	}
	
	pHeader=NULL ;
	
	return ParseTCP() ;
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
	printf("Usage: %s -r PcapFile \n",pro_name);
}

int ParseTCP()
{
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	struct pcap_pkthdr *m_headerPtr;
	const u_char *m_dataPtr ;
	
	if ((adhandle = pcap_open_offline(pcapFile,errbuf)) == NULL)
	{
		err_sys("Can't open cap file");
	}
	
	bpf_u_int32 net_ip;
	bpf_u_int32 net_mask;
	struct bpf_program fcode;
	pcap_lookupnet("eth0", &net_ip, &net_mask, errbuf);
	
	if (pcap_compile(adhandle, &fcode ,"" , 1, net_mask) < 0)
	{
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(adhandle));exit(1);
	}

	if(pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(adhandle));exit(1);
	}

	int index = 0 ;
	
	printf( "[INFO] Begin to Parse %s ...\n" , pcapFile) ;
	while(pcap_next_ex(adhandle, &m_headerPtr, &m_dataPtr)>0)
	{
	//	printf( "MATCH[%d]: PcapIndex is %d , (INFO: %s:%d --> %s:%d ) .\n" , matchCount , index , sip ,HexToLong(m_dataPtr+34 , 2 ), dip , HexToLong(m_dataPtr+36 , 2 ) ) ;
		index++ ;
		if( HexToLong(m_dataPtr+12 , 2 ) == 0x800 && HexToLong(m_dataPtr+23 ,1 ) == 0x06 )
		{
			ParseOnePcap(m_headerPtr, m_dataPtr);
		}
	}
	printf( "[INFO] End to Parse , Total Pcap Count: %d .\n" , index ) ;
	WriteTCPDialog() ;
	
	return 0 ;
}

int ParseOnePcap(struct pcap_pkthdr *m_headerPtr , const u_char *m_dataPtr)
{
	char sip[20] ;
	char dip[20] ;
	LPTCPDialog pDialog ;
	HexToIP( m_dataPtr+26 , sip ) ;
	HexToIP( m_dataPtr+30 , dip ) ;
	
	pDialog = getDialogByIPPort( sip , HexToLong(m_dataPtr+34 , 2 ) , dip , HexToLong(m_dataPtr+36 , 2 ) ) ;

	pDialog->pcapcount++;
	int len_iphead = (HexToLong(m_dataPtr+14,1) & 0x0F )<<2 ;
	int len_total = HexToLong(m_dataPtr+16,2) ;
	int len_tcphead = HexToLong(m_dataPtr+46,1)>>2 ;
//	printf( "len_total:%d ; len_iphead:%d ; len_tcphead:%d \n",len_total , len_iphead , len_tcphead ) ;
	int lenData = len_total - len_iphead - len_tcphead;
//	printf( "==> lenData:%d \n" , lenData ) ;
	if( lenData > 0 )
	{
		int len= lenData + pDialog->len ;
		char * pchar = new char[len] ;
		memcpy( pchar , pDialog->content , pDialog->len  ) ;
		memcpy( pchar+pDialog->len , m_dataPtr+14+len_iphead+len_tcphead , lenData ) ;
		if( pDialog->len == 0 ) delete pDialog->content ;
		pDialog->content = pchar ;
		pDialog->len = len ;
	}
}

LPTCPDialog getDialogByIPPort(char * sip , int sport , char * dip , int dport )
{
	LPTCPDialog p=NULL;
	int flag = 0 ;
	if( pHeader == NULL )
	{
		LPTCPDialog q = new TCPDialog ;
		strcpy(q->IP1,sip);
		strcpy(q->IP2,dip);
		q->Port1 = sport ;
		q->Port2 = dport ;
		q->len = 0 ;
		q->Next = NULL ;
		q->pcapcount = 0 ;
		pHeader = q ;
	}
	p=pHeader ;
	while(1)
	{
		if( (strcmp(p->IP1 , sip) == 0 && sport == p->Port1 && strcmp(p->IP2 , dip) == 0 && dport == p->Port2 ) || (strcmp(p->IP2 , sip) == 0 && sport == p->Port2 && strcmp(p->IP1 , dip) == 0 && dport == p->Port1 ) )
		{
			flag = 1 ;
			break ;
		}

		if( p->Next != NULL ) 
			p=p->Next ;
		else
			break ;
	}

	if( flag == 0 )
	{
		LPTCPDialog q = new TCPDialog ;
		strcpy(q->IP1,sip);
		strcpy(q->IP2,dip);
		q->Port1 = sport ;
		q->Port2 = dport ;
		q->len = 0 ;
		q->pcapcount = 0 ;
		q->Next = NULL ;
		p->Next = q ;
		p=p->Next ;
	}

	return p ;
}

void WriteTCPDialog()
{
	LPTCPDialog p ;
	char filename[100] ;
	for( p=pHeader ; p!=NULL ; p=p->Next )
	{
		sprintf( filename , "%s_%ld_%s_%ld.tcp" , p->IP1 , p->Port1 , p->IP2 , p->Port2 ) ;
		printf( "[INFO] FileName: %s ; ContentLen: %d ; PcapCount: %d !\n" , filename , p->len , p->pcapcount) ;
		if( p->len > 0 )
		{
			FILE * pFile ;
			pFile = fopen( filename , "w" ) ;
			fwrite( p->content , p->len , 1 , pFile) ;
			fclose( pFile ) ;
		}
	}

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

