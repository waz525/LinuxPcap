#include "ChangePcap.h"

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
				ShowVersion("2.2");
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
	
//	printf("%s ---> %d --- %x\n" , types , type , type );
	
		
	if( flag != 31) 
	{
		ShowHelp( argv[0] ) ;
		return 0 ;
	}

	
	int check = 0 ;
	if( strcmp(types , "RepSIP") == 0 ) 
	{
		type |= 1<<0 ;
		check = CheckString(oldpara,2) + CheckString(newpara,2) ;
	}
	else if( strcmp(types , "RepDIP") == 0 ) 
	{
		type |= 1<<1 ;
		check = CheckString(oldpara,2) + CheckString(newpara,2) ;
	}
	else if( strcmp(types , "RepIP") == 0 ) 
	{
		type |= 1<<0 ;
		type |= 1<<1 ;
		check = CheckString(oldpara,2) + CheckString(newpara,2) ;
	}
	else if( strcmp(types , "RepSMac") == 0 ) 
	{
		type |= 1<<2 ;
		check = CheckString(oldpara,3) + CheckString(newpara,3) ;
	}
	else if( strcmp(types , "RepDMac") == 0 ) 
	{
		type |= 1<<3 ;
		check = CheckString(oldpara,3) + CheckString(newpara,3) ;
	}
	else if( strcmp(types , "RepMac") == 0 ) 
	{
		type |= 1<<2 ;
		type |= 1<<3 ;
		check = CheckString(oldpara,3) + CheckString(newpara,3) ;
	}
	else if( strcmp(types , "SetSMacBySPort") == 0 ) 
	{
		type |= 1<<4 ;
		check = CheckString(oldpara,1) + CheckString(newpara,3) ;
	}
	else if( strcmp(types , "SetSMacByDPort") == 0 ) 
	{
		type |= 1<<5 ;
		check = CheckString(oldpara,1) + CheckString(newpara,3) ;
	}
	else
	{
		printf("ERROR: type(%s) is not support , run '%s -h' to get help !!!\n" , types , argv[0] ) ;
		return 0 ;
	}

	if( check > 0 ) 
	{
		return 0 ;
	}
	
	printf("INFO: Change %s : %s --> %s ( %s --> %s )\n",types,oldfile,newfile,oldpara,newpara);

	
	return ChangePcap() ;
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
	printf("Usage: %s -r oldPcapFile -w newPcapFile -t type -o oriPara -n newPara\n",pro_name);
	printf("         type: RepIP/RepSIP/RepDIP/RepMac/RepSMac/RepDMac\n");
	printf("         type: SetSMacBySPort/SetSMacByDPort\n");
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
 		MsgLen = m_headerPtr->caplen ;
 		Msg = new u_char[MsgLen] ;
 		bzero( Msg ,sizeof(Msg) ) ;
		memcpy( Msg , m_dataPtr , m_headerPtr->caplen ) ;
		ChangeMsg( Msg , MsgLen ) ;
		pcap_dump((u_char*)dumpfile , m_headerPtr, Msg) ;
		index++ ;
		delete Msg ;
	}
	printf("INFO: ChangePcap run over !!!\n");
	return 0 ;
}

int ChangeMsg( u_char *Msg  , int MsgLen ) 
{
	u_char oldParaInt[10] ;
	int len_iphead = (HexToLong(Msg+LEN_ETHERNET,1) & 0x0F )<<2 ;
	int len_tcphead = HexToLong(Msg+LEN_ETHERNET+len_iphead+12,1)>>2 ;
	
	if( ( type& 1<<0) > 0  || ( type& 1<<1) > 0 )
	{
		IPToChar(oldpara , oldParaInt )  ;

		//Replace SrcIPAddr
		if( ( type& 1<<0) > 0  && CompareInt( Msg+LEN_ETHERNET+12 , oldParaInt , 4 ) == 1 )
		{
			IPToChar(newpara , Msg+LEN_ETHERNET+12 )  ;	
		}
	
		//Replace DstIPAddr
		if( ( type& 1<<1) > 0  &&  CompareInt( Msg+LEN_ETHERNET+16 , oldParaInt , 4 ) == 1 )
		{
			IPToChar(newpara , Msg+LEN_ETHERNET+16 )  ;	
		}
	
		HeaderChecksum(Msg) ;
	}
	
	if( ( type& 1<<2) > 0  || ( type& 1<<3) > 0 )
	{
		MacToChar(oldpara , oldParaInt )  ;

		//Replace SrcMac
		if( ( type& 1<<2) > 0  && CompareInt( Msg+6 , oldParaInt , 6 ) == 1 )
		{
			MacToChar(newpara , Msg+6 )  ;	
		}
	
		//Replace DstMac
		if( ( type& 1<<3) > 0  &&  CompareInt( Msg , oldParaInt , 6 ) == 1 )
		{
			MacToChar(newpara , Msg )  ;	
		}
	}
	
	if( ( type& 1<<4) > 0  && atoi(oldpara) ==  HexToLong(Msg+LEN_ETHERNET+len_iphead , 2 ) )
	{
		MacToChar(newpara , Msg+6 )  ;	
	}
	
	if( ( type& 1<<5) > 0  && atoi(oldpara) ==  HexToLong(Msg+LEN_ETHERNET+len_iphead+2 , 2 ) )
	{
		MacToChar(newpara , Msg+6 )  ;	
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

// Compare two int str
// str1 == str2 : return 1 ;else return 0
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

// reset IP header checksum
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

//type: 1 port ; 2 ip ; 3 mac 
int CheckString( char * str , int type )
{
	int rst = 0 ;
	switch( type )
	{
	case 1:
		for( int i = 0 ; str[i]!='\0' ; i++ )
		{
			if( ! ( str[i]>= '0' && str[i]<= '9' ))
			{
				printf("ERROR: Para port (%s) is err !!!\n", str );
				rst = 1 ;
				break ;
			}
		}
		break ;
	case 2:
		for( int i = 0 ; str[i]!='\0' ; i++ )
		{
			if( ! ( ( str[i]>= '0' && str[i]<= '9' ) || (str[i] == '.' ) ) )
			{
				printf("ERROR: Para ip (%s) is err !!!\n", str );
				rst = 1 ;
				break ;
			}
		}
		break ;
	case 3:
		for( int i = 0 ; str[i]!='\0' ; i++ )
		{
			if(! ( ( str[i]>= '0' && str[i]<= '9' ) || (str[i]>= 'A' && str[i]<= 'F') || (str[i]>= 'a' && str[i]<= 'f') || (str[i] == ':' ) ) )
			{
				printf("ERROR: Para mac (%s) is err !!!\n" , str );
				rst = 1 ;
				break ;
			}
		}
		break ;
	}
	return rst ;
}
