#include "ChangePcapIP.h"

int main( int argc , char ** argv )
{
	int ch ;
	int flag = 0 ;
	type = 0 ;
	char types[20] ;
	if( argc > 1 )
	{
		while((ch = getopt(argc,argv,"o:n:w:t:r:vVhH*"))!= -1)
		{
			switch(ch)
			{
			case 'v':
			case 'V':
				ShowVersion("2.0");
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
				strcpy(oldpara , optarg);
				flag |= 1<<2 ;
				break ;
			case 'n':
				strcpy(newpara , optarg);
				flag |= 1<<3 ;
				break ;
			case 't':
				strcpy(types , optarg);
				flag |= 1<<4 ;
				break ;
			}
		}
	}
	
	if( strstr(types , "SIP") != 0 ) 
	{
		type |= 1<<0 ;
	}
	else if( strstr(types , "DIP") != 0 ) 
	{
		type |= 1<<1 ;
	}
	else if( strstr(types , "SMAC") != 0 ) 
	{
		type |= 1<<2 ;
	}
	else if( strstr(types , "SMAC") != 0 ) 
	{
		type |= 1<<3 ;
	}
	else if( strstr(types , "IP") != 0 ) 
	{
		type |= 1<<0 ;
		type |= 1<<1 ;
	}
	else if( strstr(types , "MAC") != 0 ) 
	{
		type |= 1<<2 ;
		type |= 1<<3 ;
	}
	
	if( flag != 31 || type == 0  ) 
	{
		ShowHelp( argv[0] ) ;
		return 0 ;
	}

	
	printf("INFO: Change %s : %s --> %s ( %s ---> %s )\n",types,oldfile,newfile,oldpara,newpara);
	
	return ChangePcap() ;
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
	printf("Usage: %s -r oldfile -w newfile -t type -o oldPara -n newPara\n",pro_name);
	printf("         type: IP/MAC/SIP/DIP/SMAC/DMAC\n");
}

int ChangePcap()
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
//	AnalysePacket(m_headerPtr,m_dataPtr) ;
 		MsgLen = m_headerPtr->caplen ;
 		Msg = new u_char[MsgLen] ;
 		bzero( Msg ,sizeof(Msg) ) ;
		memcpy( Msg , m_dataPtr , m_headerPtr->caplen ) ;
		ChangeMsg( Msg , MsgLen ) ;
		pcap_dump((u_char*)dumpfile , m_headerPtr, Msg) ;
		index++ ;
//	printf("\rCount ===> %d",index) ;
		delete Msg ;
	}
	//printf("\n");
	printf("INFO: ChangePcapIP run over !!!\n");
	return 0 ;
}

int ChangeMsg( u_char *Msg  , int MsgLen ) 
{
	u_char oldParaInt[10] ;
	
	if( ( type& 1<<0) > 0  || ( type& 1<<1) > 0 )
	{
		IPToChar(oldpara , oldParaInt )  ;

		//SrcIPAddr
		if( ( type& 1<<0) > 0  && CompareInt( Msg+26 , oldParaInt , 4 ) == 1 )
		{
			IPToChar(newpara , Msg+26 )  ;	
		}
	
		//DstIPAddr
		if( ( type& 1<<1) > 0  &&  CompareInt( Msg+30 , oldParaInt , 4 ) == 1 )
		{
			IPToChar(newpara , Msg+30 )  ;	
		}
	
		HeaderChecksum(Msg) ;
	}
	
	if( ( type& 1<<2) > 0  || ( type& 1<<3) > 0 )
	{
		MacToChar(oldpara , oldParaInt )  ;

		//SrcMac
		if( ( type& 1<<2) > 0  && CompareInt( Msg+6 , oldParaInt , 6 ) == 1 )
		{
			MacToChar(newpara , Msg+6 )  ;	
		}
	
		//DstMac
		if( ( type& 1<<3) > 0  &&  CompareInt( Msg , oldParaInt , 6 ) == 1 )
		{
			MacToChar(newpara , Msg )  ;	
		}

	}
}

int MacToChar( char * mac , u_char * rst)
{
	char temp[5] ;
	int ind = 0 ;
	int i = 0 ;
	int ind_rst = 0 ;
	while( mac[ind] != '\0' )
	{
		bzero(temp,sizeof(temp)) ;
		i=0 ;
		while( mac[ind] != ':' &&  mac[ind] != '\0' )
		{
			temp[i] = mac[ind] ;
			i++ ; ind++ ;
		}
		if( mac[ind] == ':' ) ind++ ;
		temp[i]='\0' ;
		rst[ind_rst]=HexToChar(temp,2);
		ind_rst++ ;
	}
	return ind_rst ;
}

long HexToChar(char * hex,int len)
{
//	printf( " HexToChar ===> %s \n" , hex ) ;
	long res = 0 ;
	int t ;
	for(int i = 0 ; i<len ; i++)
	{
		t=0 ;
		switch(hex[i])
		{
		case 'A':
		case 'a':
			t=10 ; break ;
		case 'B':
		case 'b':
			t=11; break ;
		case 'C':
		case 'c':
			t=12 ; break ;
		case 'D':
		case 'd':
			t=13; break ;
		case 'E':
		case 'e':
			t=14 ; break ;
		case 'F':
		case 'f':
			t=15 ; break ;
		default :
			t= hex[i] - '0' ;
		}
		res = res * 16 + t ;
	}
	return res ;
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

void HeaderChecksum(u_char *Msg )
{
	int t1=0 ;
	int cksum = 0 ;
	Msg[24] = 0 ;
	Msg[25] = 0 ;
	for( int i=14 ; i<33 ; i+=2)
	{
//		printf( "---> %2x %2x \n " , Msg[i] , Msg[i+1] ) ;
		cksum+=*(Msg+i+1) ;
		cksum+=*(Msg+i)<<8 ;
//		printf( "cksum = %x\n" , cksum );
	}
	while(cksum > 0xffff)
	{
		cksum = (cksum >> 16) + (cksum & 0xffff);
	}
	//printf( "cksum = %x\n" , cksum );
	//printf( "--> cksum = %x\n" , ~cksum& 0xffff);
	Msg[24]=(~cksum& 0xffff)>>8 ;
	Msg[25]=(~cksum& 0xff );
//	printf( "INFO: Header Checksum \n" ) ;
	
}
