#include "ChangePcapIP.h"

int main( int argc , char ** argv )
{
	int ch ;
	int flag = 0 ;
	if( argc > 1 )
	{
		while((ch = getopt(argc,argv,"o:n:w:r:vVhH*"))!= -1)
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
				strcpy(oldfile , optarg);
				flag |= 1<<0 ;
				break ;
			case 'w':
				strcpy(newfile , optarg);
				flag |= 1<<1 ;
				break ;
			case 'o':
				strcpy(oldip , optarg);
				flag |= 1<<2 ;
				break ;
			case 'n':
				strcpy(newip , optarg);
				flag |= 1<<3 ;
				break ;
			}
		}
	}
	if( flag != 15 ) 
	{
		ShowHelp( argv[0] ) ;
		return 0 ;
	}

	printf("INFO: %s --> %s ( %s ---> %s )\n",oldfile,newfile,oldip,newip);
	ChangePcapIP() ;
	
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
	printf("Usage: %s -r oldfile -o oldIP -n newIP -w newfile\n",pro_name);
}

int ChangePcapIP()
{
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	struct pcap_pkthdr *m_headerPtr;
	const u_char *m_dataPtr ;
	u_char * dataPtr ;
	
	if ((adhandle = pcap_open_offline(oldfile,errbuf)) == NULL)
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
	pcap_dumper_t *dumpfile;
	dumpfile=pcap_dump_open(adhandle,newfile);
	
	u_char * Msg ;
	int MsgLen = 0 ;

	while(pcap_next_ex(adhandle, &m_headerPtr, &m_dataPtr)>0)
	{
//		AnalysePacket(m_headerPtr,m_dataPtr) ;
 		MsgLen = m_headerPtr->caplen ;
 		Msg = new u_char[MsgLen] ;
 		bzero( Msg ,sizeof(Msg) ) ;
		memcpy( Msg , m_dataPtr , m_headerPtr->caplen ) ;
		ChangeIP( Msg , MsgLen ) ;
		pcap_dump((u_char*)dumpfile , m_headerPtr, Msg) ;
		index++ ;
		printf("\rCount ===> %d",index) ;
		delete Msg ;
	}
	//printf("\n");
	printf("\rINFO: ChangePcapIP run over !!!\n");
}

int ChangeIP( u_char *Msg  , int MsgLen ) 
{
	u_char oldIpInt[4] ;	
//	u_char newIpInt[4] ;
	IPToChar(oldip , oldIpInt )  ;	
//	IPToChar(newip , newIpInt )  ;
	
	//SrcIPAddr
	if( CompareInt( Msg+26 , oldIpInt , 4 ) == 1 )
	{
		IPToChar(newip , Msg+26 )  ;	
	}
	
	//DstIPAddr
	if( CompareInt( Msg+30 , oldIpInt , 4 ) == 1 )
	{
		IPToChar(newip , Msg+30 )  ;	
	}
	
	
	
}

int IPToChar( char * ip , u_char * rst )
{	
	char temp[5] ;
	int ind = 0 ;
	int i = 0 ;
	int ind_rst = 0 ;
	while( ip[ind] != '\0' )
	{
		bzero(temp,sizeof(temp)) ;
		i=0 ;
		while( ip[ind] != '.' &&  ip[ind] != '\0' )
		{
			temp[i] = ip[ind] ;
			i++ ; ind++ ;
		}
		if( ip[ind] == '.' ) ind++ ;
		temp[i]='\0' ;
		rst[ind_rst++]= atol(temp) ;
	}
	return ind_rst ;
}

int CompareInt( u_char * str1 , u_char * str2 , int len ) 
{
	int rst = 1 ;
	for( int ind = 0 ; ind < len ; ind++ )
	{
		if( str1[ind] != str2[ind] )
		{
			rst = 0 ;
			break ;
		}
	}
	return rst ;
}
