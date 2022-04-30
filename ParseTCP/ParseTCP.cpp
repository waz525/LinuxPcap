#include "ParseTCP.h"

int main( int argc , char ** argv )
{
	char ch ;
	int flag = 0 ;
	isDebugMode = 0 ;
	countDialog = 0 ;
	pHeader = NULL ;
	maxDialog = 0 ;
	countFile = 0 ;
	bzero(filterStr,sizeof(filterStr));
	
	if( argc > 1 )
	{
		//opterr = 0 ;
		while((ch = getopt(argc,argv,"r:c:f:dvh*"))!= -1)
		{
			switch(ch)
			{
			case 'v':
			case 'V':
				ShowVersion("3.1");
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
			case 'f':
				strcpy(filterStr,optarg);
				break ;
			case 'd':
				isDebugMode = 1 ;
				break ;
			case 'c':
				maxDialog = atoi((char*)optarg) ;
				break ;
			}
		}
		if( optopt != 0 ) flag = 0 ;
	}
	
	
		
	if( flag != 1 ) 
	{
		ShowHelp( argv[0] ) ;
		return 0 ;
	}
	
	printf("[INFO] PcapFile: %s ; Filter: \"%s\" ; maxDialogCount: %d ; DebugMode: %d !\n" , pcapFile , filterStr ,  maxDialog , isDebugMode ) ;
	ParseTCP() ;
	printf("[INFO] Total Pcap Count: %d , Parse %d Dialogs , Write %d files !\n" , pcapIndex , countDialog , countFile ) ;
	
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
	printf("Usage: %s -r PcapFile [-f filter] [-c maxDialogCount] [-d] \n",pro_name);
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
	
	if (pcap_compile(adhandle, &fcode , filterStr , 1, net_mask) < 0)
	{
		fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(adhandle));exit(1);
	}

	if(pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(adhandle));exit(1);
	}

	pcapIndex = 0 ;
	
	printf( "[INFO] Begin to Parse ... \n" , pcapFile) ;
	if(isDebugMode ==1 ) printf("[DEBUG] pcapIndex: seqnum -- acknum -- initSeqNum -- initAckNum -- offset -- lenData -- IP1:Port1 -- IP2:Port2 -- seqFlag -- pcapcount:Dialogindex:countDialog\n") ;
	while(pcap_next_ex(adhandle, &m_headerPtr, &m_dataPtr)>0)
	{
		pcapIndex++ ;
		ParseOnePcap(m_headerPtr, m_dataPtr);
	}
	printf( "[INFO] End to Parse , Begin to Write File ...\n" ) ;
	WriteTCPDialog() ;	
	ReleaseTCPDialog();
	
	return 0 ;
}

void ParseOnePcap(struct pcap_pkthdr *m_headerPtr , const u_char *m_dataPtr)
{
	//if not ip and tcp ; return 
	if( HexToLong(m_dataPtr+LEN_ETHERNET-2 , 2 ) != 0x800 || HexToLong(m_dataPtr+LEN_ETHERNET+9 ,1 ) != 0x06 ) return ;
	char sip[20] ;
	char dip[20] ;
	LPTCPDialog pDialog ;
	int offset = 0 ;
	
	int len_iphead = (HexToLong(m_dataPtr+LEN_ETHERNET,1) & 0x0F )<<2 ;
	int len_tcphead = HexToLong(m_dataPtr+LEN_ETHERNET+len_iphead+12,1)>>2 ;
	int len_total = HexToLong(m_dataPtr+LEN_ETHERNET+2,2) ;
	
	HexToIP( m_dataPtr+LEN_ETHERNET+12 , sip ) ;
	HexToIP( m_dataPtr+LEN_ETHERNET+16 , dip ) ;
	
	pDialog = getDialogByIPPort( sip , HexToLong(m_dataPtr+LEN_ETHERNET+len_iphead , 2 ) , dip , HexToLong(m_dataPtr+LEN_ETHERNET+len_iphead+2 , 2 ) ) ;
	if( pDialog == NULL ) return ;
	
	pDialog->pcapcount++;
	long long seqnum = HexToLongLong(m_dataPtr+LEN_ETHERNET+len_iphead+4,4) ;
	long long acknum = HexToLongLong(m_dataPtr+LEN_ETHERNET+len_iphead+8,4) ;
	if( seqnum == 0 || acknum == 0 ) pDialog->initSeqNum = 0 ;
	
	int lenData = len_total - len_iphead - len_tcphead;
	if( lenData > 0 )
	{
		if( pDialog->initSeqNum == 0 || pDialog->initAckNum == 0 )
		{
			if( pDialog->seqFlag == 0 ) 
			{
				pDialog->initSeqNum = seqnum ;
				pDialog->initAckNum = acknum ;
			}
			else
			{
				pDialog->initSeqNum = acknum ;
				pDialog->initAckNum = seqnum ;
			}
		}
		else
		{
			if( pDialog->seqFlag == 0 )
				offset = (seqnum - pDialog->initSeqNum) + (acknum - pDialog->initAckNum) ;
			else
				offset = (acknum - pDialog->initSeqNum) + (seqnum - pDialog->initAckNum) ;
		}
		if( offset < 0 ) return ;
		if(isDebugMode ==1 ) printf("[DEBUG] %04d: %lld -- %lld -- %lld -- %lld -- %d -- %d -- %s:%d -- %s:%d -- %d -- %d:%d:%d\n" , pcapIndex , seqnum , acknum , pDialog->initSeqNum , pDialog->initAckNum , offset , lenData , pDialog->IP1 , pDialog->Port1 , pDialog->IP2 , pDialog->Port2 , pDialog->seqFlag , pDialog->pcapcount , pDialog->index , countDialog) ;
		int len = offset + lenData ;
		if( len > pDialog->len ) pDialog->len = len ;
		char * pchar = new char[lenData] ;
		bzero( pchar , lenData ) ;
		memcpy( pchar , m_dataPtr+len_iphead+len_tcphead+LEN_ETHERNET , lenData ) ;
		LPTCPContent pTcpContent = getNewTcpContent( pDialog );
		pTcpContent->offset = offset ;
		pTcpContent->lenData = lenData ;
		pTcpContent->content = pchar ;
	}
}

LPTCPContent getNewTcpContent(LPTCPDialog pDialog )
{
	LPTCPContent p ;
	p = pDialog->ContentLink ; 
	while( p != NULL && p->Next != NULL)
	{
		p = p->Next ;
	}
	LPTCPContent q = new TCPContent ;
	q->Next = NULL ;
	if( p == NULL ) pDialog->ContentLink = q ;
	else p->Next = q ;
	return q ;
}

LPTCPDialog getDialogByIPPort(char * sip , int sport , char * dip , int dport )
{
	LPTCPDialog p=NULL;
	int flag = 0 ;
	if( pHeader == NULL )
	{
		LPTCPDialog q = initTCPDialog() ;
		strcpy(q->IP1,sip);
		strcpy(q->IP2,dip);
		q->Port1 = sport ;
		q->Port2 = dport ;
		pHeader = q ;
		return pHeader ;
	}
	
	p=pHeader ;

	while(1)
	{

		if( strcmp(p->IP1 , sip) == 0 && sport == p->Port1 && strcmp(p->IP2 , dip) == 0 && dport == p->Port2 )
		{
			flag = 1 ;
			p->seqFlag = 0 ;
			break ;
		}
		else if( strcmp(p->IP2 , sip) == 0 && sport == p->Port2 && strcmp(p->IP1 , dip) == 0 && dport == p->Port1 )
		{
			flag = 1 ;
			p->seqFlag = 1 ;
			break ;
		}
		
		if( p->Next != NULL ) 
			p=p->Next ;
		else
			break ;
	}

	if( flag == 0 )
	{
		if( maxDialog > 0 && countDialog == maxDialog ) return NULL ;
		LPTCPDialog q = initTCPDialog() ;
		strcpy(q->IP1,sip);
		strcpy(q->IP2,dip);
		q->Port1 = sport ;
		q->Port2 = dport ;
		p->Next = q ;
		p=p->Next ;
	}

	return p ;
}

void WriteTCPDialog()
{
	LPTCPDialog p ;
	LPTCPContent q ;
	char filename[100] ;
	for( p=pHeader ; p!=NULL ; p=p->Next )
	{
		sprintf( filename , "%s_%ld_%s_%ld.tcp" , p->IP1 , p->Port1 , p->IP2 , p->Port2 ) ;
		printf( "[INFO] Dialog %d : PcapCount: %d ; ContentLen: %d ; FileName: %s !\n" , p->index , p->pcapcount , p->len , filename) ;
		if( p->len > 0 )
		{
			FILE * pFile ;
			pFile = fopen( filename , "w" ) ;
			q=p->ContentLink ;
			while( q != NULL )
			{
				fseek( pFile , q->offset , SEEK_SET ) ;
				fwrite( q->content , q->lenData , 1 , pFile) ;
				q=q->Next ;
			}
			fclose( pFile ) ;
			countFile++ ;
		}
	}
}

void ReleaseTCPDialog()
{
	if( pHeader != NULL )
	{
		LPTCPDialog p , q;
		for( p=pHeader ; p != NULL ; p=q)
		{
			if( p->ContentLink != NULL ) 
			{
				LPTCPContent l , k ;
				for( l=p->ContentLink  ; l != NULL ; l=k)
				{
					k=l->Next ;
					delete l ;
				}				
			}
			q=p->Next ;
			delete p ;
		}
		
	}
	
}

LPTCPDialog initTCPDialog()
{
	countDialog++ ;
	LPTCPDialog q = new TCPDialog ;
	q->index = countDialog ;
	bzero( q->IP1 , sizeof(q->IP1) ) ;
	bzero( q->IP2 , sizeof(q->IP2) ) ;
	q->Port1 = 0 ;
	q->Port2 = 0 ;
	q->len = 0 ;
	q->pcapcount = 0 ;
	q->initSeqNum = 0 ;
	q->initAckNum = 0 ;
	q->seqFlag = 0 ;
	q->ContentLink = NULL ;
	q->Next = NULL ;
	return q ;
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

long long HexToLongLong(  const unsigned char * hexChar , int len )
{
	long long res=0 ;
	for( int i = 0 ; i<len ; i++)
	{
		res *= 256 ;
		res += hexChar[i] ;
	//	printf( "HexToLongLong ==> %lld -- %x\n" , res , hexChar[i] ) ;
	}
	//printf( "HexToLongLong END ===> %lld \n " , res ) ;

	return res ;
}
