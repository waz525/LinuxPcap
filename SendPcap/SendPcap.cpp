
#include "SendPcap.h"


void ShowVersion( char * version ) 
{
	printf("ReleaseVersion : %s \n",version );
	printf("The Proprietor : WAZ \n");
	printf("Last Make Time : %s %s \n" , __DATE__ , __TIME__ );
}

void ShowHelp( char * pro_name)
{
	printf("Usage: %s [option] \n",pro_name);
	printf("options : \n");
	printf("        -v : show version \n");
	printf("        -h : show help \n");
	printf("        -c cfgFile : run by cfgFile \n");
	printf("        no option : run by defualt cfgFile(./SendPcap.cfg) \n");
}

int main( int argc , char ** argv )
{
	if( argc > 1 )
	{
		int ch;
		opterr = 0;
		while((ch = getopt(argc,argv,"c:vVhH?"))!= -1)
		{
			switch(ch)
			{
			case 'v':
			case 'V':
				ShowVersion("2.3");
				break ;
			case 'h':
			case 'H':
				ShowHelp( argv[0] ) ;
				break ;
			case 'c':
				SendPacket( optarg ) ;
				break ;
			default:
				printf("Error: NOT OPTION %s !!!\n",ch);
			}
		}

	}
	else
	{
		SendPacket("./SendPcap.cfg");
	}
	return 0 ;
}




void SendPacket( char * cfgName )
{
	struct stat buf;
	int f = stat( cfgName , &buf) ; 
	if( f == -1 )
	{
		printf("Error: %s not exist !!! \n",cfgName) ;
		return ;
	}
	printf("Info: Get configure from %s ... \n",cfgName) ;
	CCfgFile m_cfgFile(cfgName,1) ;
	int PacketType ;
	PacketType = m_cfgFile.GetValueInt( "SendPcap" , "PacketType" , 1 );
	printf("Info: PacketType is %d ...\n", PacketType) ;

	switch( PacketType ) 
	{
	case 1 :
		SendPacketByDetil( &m_cfgFile ) ;
		break ;
	case 2 :
		SendPacketByHexString( &m_cfgFile ) ;
		break ;
	case 3 :
		SendPacketByCapfile( &m_cfgFile ) ;
		break ;
	default :
		printf("Error: Packet Type Error ( %d ) \n",PacketType) ;		
	}
	
}

void SendPacketByCapfile( CCfgFile * m_cfgFile )
{
	char dev[10] ;
	int PacketNum ;
	char PacketHexString[1024] ;
	int RepeatNum ;
	int PacketInterval ;
	int Interval ;
	char SrcIPAddr[20] ;
	char SrcMACAddr[20] ;
	char SrcPort[10] ;
	char DstIPAddr[20] ;
	char DstMACAddr[20] ;
	char DstPort[10] ;
	char capfile[255] ;
	
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	struct pcap_pkthdr *m_headerPtr;
	const u_char *m_dataPtr ;
	
	m_cfgFile->GetValue( "SendPcap" , "Interface" , dev , "" ) ;
	if( strlen(dev) > 0 ) printf("Info: Interface is %s ...\n", dev) ;
	else
	{
		printf("Error: interface config error !\n") ;
		return ;
	}
	m_cfgFile->GetValue( "SendPcap" , "PacketFile" , capfile , "" ) ;
	if( strlen(capfile) > 0 ) printf("Info: Capfile is %s ...\n", capfile) ;
	else
	{
		printf("Error: capfile config error !\n") ;
		return ;
	}
	PacketNum = m_cfgFile->GetValueInt( "SendPcap" , "PacketNum" , 1 );
	printf("Info: PacketNum is %d ...\n", PacketNum) ;
	PacketInterval = m_cfgFile->GetValueInt( "SendPcap" , "PacketInterval" , 100 );
	printf("Info: PacketInterval is %d...\n", PacketInterval) ;
	
	if ((adhandle = pcap_open_offline(capfile,errbuf)) == NULL)
	{
		printf("Error: Can't open cap file\n");
		return ;
	}

	int f = 1 ;
	while(pcap_next_ex(adhandle, &m_headerPtr, &m_dataPtr)>0)
	{
		char itemName[10] ;		
		sprintf( itemName , "Packet_%d" ,  f ) ;
		  	
		printf( "\n========================== Begin %s ==========================\n" , itemName);
		
		m_cfgFile->GetValue( itemName , "SrcPort" ,  SrcPort , "") ;
		m_cfgFile->GetValue( itemName , "SrcIPAddr" , SrcIPAddr , "") ;
		m_cfgFile->GetValue( itemName , "SrcMACAddr"  , SrcMACAddr , "" );
		m_cfgFile->GetValue( itemName , "DstIPAddr" ,  DstIPAddr , "") ;
		m_cfgFile->GetValue( itemName , "DstMACAddr" , DstMACAddr , "") ;
		m_cfgFile->GetValue( itemName , "DstPort" , DstPort ,"" ) ;
		RepeatNum = m_cfgFile->GetValueInt( itemName , "RepeatNum" , 1) ;
		Interval = m_cfgFile->GetValueInt( itemName , "Interval" , 1 ) ;
		
		if( strlen(SrcMACAddr) > 0 ) printf("Info: [%s] SrcMACAddr is %s ...\n", itemName , SrcMACAddr ) ;
		if( strlen(SrcIPAddr) > 0 ) printf("Info: [%s] SrcIPAddr is %s ...\n", itemName , SrcIPAddr ) ;
		if( strlen(SrcPort) > 0 ) printf("Info: [%s] SrcPort is %s ...\n", itemName , SrcPort ) ;
		if( strlen(DstMACAddr) > 0 ) printf("Info: [%s] DstMACAddr is %s ...\n", itemName , DstMACAddr ) ;
		if( strlen(DstIPAddr) > 0 ) printf("Info: [%s] DstIPAddr is %s ...\n", itemName , DstIPAddr ) ;
		if( strlen(DstPort) > 0 ) printf("Info: [%s] DstPort is %s ...\n", itemName , DstPort ) ;
		printf("Info: [%s] RepeatNum is %d ...\n", itemName , RepeatNum ) ;
		printf("Info: [%s] Interval is %d ...\n", itemName , Interval ) ;
		printf("========================================================\n");
		
		u_char Msg[2048] ;
		//bzero( Msg , sizeof(Msg) ) ;
		int MsgLen = m_headerPtr->caplen ;
		
		memcpy( Msg , m_dataPtr , m_headerPtr->caplen ) ;
		
		if( strlen(DstMACAddr) > 0 ) MacToChar( DstMACAddr , Msg );
		if( strlen(SrcMACAddr) > 0 ) MacToChar( SrcMACAddr , Msg+6 );
		
		if( strlen(SrcIPAddr) > 0 ) IPToChar( SrcIPAddr , Msg+26);
		if( strlen(DstIPAddr) > 0 ) IPToChar( DstIPAddr , Msg+30);
		
		if( strlen(SrcPort) > 0 ) LongToChar( atol(SrcPort) , Msg+34 , 2 ) ;
		if( strlen(DstPort) > 0 ) LongToChar( atol(DstPort) , Msg+36 , 2 ) ;
		
		// read msg
		printf(" MsgLen: %d\n", MsgLen);
		for( int d =0 ;d<MsgLen; d++ )
		{
			if( d!=0 && d%8 == 0 ) printf("\n") ;
			printf(" 0x%.2x ,",Msg[d]);
		}
		
		printf("\n========================================================\n");
		
		sendPcap( dev , Msg , MsgLen , RepeatNum , Interval ) ;
		printf( "==========================  END %s  ==========================\n\n" , itemName);
		
		if( f == PacketNum ) break ;
		usleep( PacketInterval*1000 ) ;
		f++ ;		
	}
}



void SendPacketByHexString( CCfgFile * m_cfgFile ) 
{
	char dev[10] ;
	int PacketNum ;
	char PacketHexString[1024] ;
	int RepeatNum ;
	int PacketInterval ;
	int Interval ;
	char SrcIPAddr[20] ;
	char SrcMACAddr[20] ;
	char SrcPort[10] ;
	char DstIPAddr[20] ;
	char DstMACAddr[20] ;
	char DstPort[10] ;
	
	m_cfgFile->GetValue( "SendPcap" , "Interface" , dev , "" ) ;
	if( strlen(dev) > 0 ) printf("Info: Interface is %s ...\n", dev) ;
	else
	{
		printf("Error: interface config error !\n") ;
		return ;
	}
	PacketNum = m_cfgFile->GetValueInt( "SendPcap" , "PacketNum" , 1 );
	printf("Info: PacketNum is %d ...\n", PacketNum) ;
	PacketInterval = m_cfgFile->GetValueInt( "SendPcap" , "PacketInterval" , 100 );
	printf("Info: PacketInterval is %d ...\n", PacketInterval) ;
	
	for(int f = 1 ; f <= PacketNum ; f++ )
	{
		if( f!= 1 ) usleep( PacketInterval * 1000 ) ;
		char itemName[10] ;
		sprintf( itemName , "Packet_%d" ,  f ) ;
		  	
		printf( "\n========================== Begin %s ==========================\n" , itemName);
		
		m_cfgFile->GetValue( itemName , "PacketHexString" , PacketHexString , "" ) ;
		m_cfgFile->GetValue( itemName , "SrcPort" ,  SrcPort , "") ;
		m_cfgFile->GetValue( itemName , "SrcIPAddr" , SrcIPAddr , "") ;
		m_cfgFile->GetValue( itemName , "SrcMACAddr"  , SrcMACAddr , "" );
		m_cfgFile->GetValue( itemName , "DstIPAddr" ,  DstIPAddr , "") ;
		m_cfgFile->GetValue( itemName , "DstMACAddr" , DstMACAddr , "") ;
		m_cfgFile->GetValue( itemName , "DstPort" , DstPort ,"" ) ;
		RepeatNum = m_cfgFile->GetValueInt( itemName , "RepeatNum" , 1) ;
		Interval = m_cfgFile->GetValueInt( itemName , "Interval" , 1 ) ;
		
		if( strlen(PacketHexString) > 0 ) printf("Info: [%s] PacketHexString is %s ...\n", itemName , PacketHexString ) ;
		else
		{
			printf("Error: [%s] PacketHexString config error !\n", itemName) ;
			return ;
		}
		if( strlen(SrcMACAddr) > 0 ) printf("Info: [%s] SrcMACAddr is %s ...\n", itemName , SrcMACAddr ) ;
		if( strlen(SrcIPAddr) > 0 ) printf("Info: [%s] SrcIPAddr is %s ...\n", itemName , SrcIPAddr ) ;
		if( strlen(SrcPort) > 0 ) printf("Info: [%s] SrcPort is %s ...\n", itemName , SrcPort ) ;
		if( strlen(DstMACAddr) > 0 ) printf("Info: [%s] DstMACAddr is %s ...\n", itemName , DstMACAddr ) ;
		if( strlen(DstIPAddr) > 0 ) printf("Info: [%s] DstIPAddr is %s ...\n", itemName , DstIPAddr ) ;
		if( strlen(DstPort) > 0 ) printf("Info: [%s] DstPort is %s ...\n", itemName , DstPort ) ;
		printf("Info: [%s] RepeatNum is %d ...\n", itemName , RepeatNum ) ;
		printf("Info: [%s] Interval is %d ...\n", itemName , Interval ) ;
		printf("========================================================\n");
		
		u_char Msg[1024] ;
		//bzero( Msg , sizeof(Msg) ) ;
		int MsgLen = 0 ;
		
		MsgLen += HexStringToChar( PacketHexString , Msg ) ;
		
		if( strlen(DstMACAddr) > 0 ) MacToChar( DstMACAddr , Msg );
		if( strlen(SrcMACAddr) > 0 ) MacToChar( SrcMACAddr , Msg+6 );
		
		if( strlen(SrcIPAddr) > 0 ) IPToChar( SrcIPAddr , Msg+26);
		if( strlen(DstIPAddr) > 0 ) IPToChar( DstIPAddr , Msg+30);
		
		if( strlen(SrcPort) > 0 ) LongToChar( atol(SrcPort) , Msg+34 , 2 ) ;
		if( strlen(DstPort) > 0 ) LongToChar( atol(DstPort) , Msg+36 , 2 ) ;
		
		// read msg
		printf(" MsgLen: %d\n", MsgLen);
		for( int d =0 ;d<MsgLen; d++ )
		{
			if( d!=0 && d%8 == 0 ) printf("\n") ;
			printf(" 0x%.2x ,",Msg[d]);
		}
		printf("\n========================================================\n");
		
		sendPcap( dev , Msg , MsgLen , RepeatNum , Interval ) ;
		printf( "==========================  END %s  ==========================\n\n" , itemName);
	}	
}

void SendPacketByDetil( CCfgFile * m_cfgFile ) 
{
	char dev[10] ;
	int PacketNum ;
	int PacketInterval ;
	char SrcIPAddr[20] ;
	char SrcMACAddr[20] ;
	char SrcPort[10] ;
	char DstIPAddr[20] ;
	char DstMACAddr[20] ;
	char DstPort[10] ;
	char PacketContent[1024] ;
	int RepeatNum ;
	int Interval ;
	
	//m_cfgFile.ShowCfg();

	m_cfgFile->GetValue( "SendPcap" , "Interface" , dev , "" ) ;
	PacketNum = m_cfgFile->GetValueInt( "SendPcap" , "PacketNum" , 1 );
	if( strlen(dev) > 0 ) printf("Info: Interface is %s ...\n", dev) ;
	else
	{
		printf("Error: interface config error !\n") ;
		return ;
	}
	printf("Info: PacketNum is %d ...\n", PacketNum) ;
	PacketInterval = m_cfgFile->GetValueInt( "SendPcap" , "PacketInterval" , 100 );
	printf("Info: PacketInterval is %d ...\n", PacketInterval) ;
	
	for(int f = 1 ; f <= PacketNum ; f++ )
	{
		if( f!= 1 ) usleep( PacketInterval * 1000 ) ;
		char itemName[10] ;
		sprintf( itemName , "Packet_%d" ,  f ) ;
		  	
		printf( "\n========================== Begin %s ==========================\n" , itemName);
		
		m_cfgFile->GetValue( itemName , "SrcPort" ,  SrcPort , "") ;
		m_cfgFile->GetValue( itemName , "SrcIPAddr" , SrcIPAddr , "") ;
		m_cfgFile->GetValue( itemName , "SrcMACAddr"  , SrcMACAddr , "" );
		m_cfgFile->GetValue( itemName , "DstIPAddr" ,  DstIPAddr , "") ;
		m_cfgFile->GetValue( itemName , "DstMACAddr" , DstMACAddr , "") ;
		m_cfgFile->GetValue( itemName , "DstPort" , DstPort ,"" ) ;
		m_cfgFile->GetValue( itemName , "PacketContent" , PacketContent , "" ) ;
		RepeatNum = m_cfgFile->GetValueInt( itemName , "RepeatNum" , 1) ;
		Interval = m_cfgFile->GetValueInt( itemName , "Interval" , 1 ) ;


		if( strlen(SrcMACAddr) > 0 ) printf("Info: [%s] SrcMACAddr is %s ...\n", itemName , SrcMACAddr ) ;
		else
		{
			printf("Error: [%s] SrcMACAddr config error !\n", itemName) ;
			return ;
		}
		if( strlen(SrcIPAddr) > 0 ) printf("Info: [%s] SrcIPAddr is %s ...\n", itemName , SrcIPAddr ) ;
		else
		{
			printf("Error: [%s] SrcIPAddr config error !\n", itemName) ;
			return ;
		}
		if( strlen(SrcPort) > 0 ) printf("Info: [%s] SrcPort is %s ...\n", itemName , SrcPort ) ;
		else
		{
			printf("Error: [%s] SrcPort config error !\n", itemName) ;
			return ;
		}
		if( strlen(DstMACAddr) > 0 ) printf("Info: [%s] DstMACAddr is %s ...\n", itemName , DstMACAddr ) ;
		else
		{
			printf("Error: [%s] DstMACAddr config error !\n", itemName) ;
			return ;
		}
		if( strlen(DstIPAddr) > 0 ) printf("Info: [%s] DstIPAddr is %s ...\n", itemName , DstIPAddr ) ;
		else
		{
			printf("Error: [%s] DstIPAddr config error !\n", itemName) ;
			return ;
		}
		if( strlen(DstPort) > 0 ) printf("Info: [%s] DstPort is %s ...\n", itemName , DstPort ) ;
		else
		{
			printf("Error: [%s] DstPort config error !\n", itemName) ;
			return ;
		}
		if( strlen(PacketContent) > 0 ) printf("Info: [%s] PacketContent is %s ...\n", itemName , PacketContent ) ;
		printf("Info: [%s] RepeatNum is %d ...\n", itemName , RepeatNum ) ;
		printf("Info: [%s] Interval is %d ...\n", itemName , Interval ) ;
		printf("========================================================\n");
  	
  	
		u_char Msg[1024] ;
		//bzero( Msg , sizeof(Msg) ) ;
		int MsgLen = 0 ;
		
		/* Ethernet */
		// Dst MAC
		MsgLen += MacToChar( DstMACAddr , Msg+MsgLen );
		// Src MAC
		MsgLen += MacToChar( SrcMACAddr , Msg+MsgLen );
		// Ethernet protocol ID
		// defult IP
		Msg[MsgLen] = 0x08 ; MsgLen++ ;
		Msg[MsgLen] = 0x00 ; MsgLen++ ;
		
		/* Internet protocol	*/
		// version ( 4 ) and hearder length ( 20 )
		Msg[MsgLen] = 0x45 ; MsgLen++ ;	
		//differentiated services field ( defualt : 0x00 ) 
		Msg[MsgLen] = 0x00 ; MsgLen++ ;
		//total length ( use 74 as defualt )
		//chage at end 
		MsgLen += LongToChar( 74 , Msg+MsgLen , 2 ) ;	
		// Identification: 0x8c2c (35884)
		MsgLen += LongToChar( 35884 , Msg+MsgLen , 2 ) ;
		//Flags: 0x04 (Don't Fragment) and  Fragment offset: 0
		Msg[MsgLen] = 0x40 ; MsgLen++ ;
		Msg[MsgLen] = 0x00 ; MsgLen++ ;
		//Time to live: 60
		Msg[MsgLen] = 60 ; MsgLen++ ;
		//Protocol: TCP (0x06)
		Msg[MsgLen] = 0x06 ; MsgLen++ ;
		//Header checksum: 0x3046 [correct]
		Msg[MsgLen] = 0x30 ; MsgLen++ ;
		Msg[MsgLen] = 0x46 ; MsgLen++ ;
		// Src IP
		MsgLen += IPToChar( SrcIPAddr , Msg+MsgLen);
		// Dst IP
		MsgLen += IPToChar( DstIPAddr , Msg+MsgLen);
		
		/* Transmission Control Protocol */
		//Source port
		MsgLen += LongToChar( atol(SrcPort) , Msg+MsgLen , 2 ) ;
		//Destination port
		MsgLen += LongToChar( atol(DstPort) , Msg+MsgLen , 2 ) ;
		//Sequence number (relative sequence number)
		Msg[MsgLen] = 0xd7 ; MsgLen++ ;
		Msg[MsgLen] = 0x4e ; MsgLen++ ;
		Msg[MsgLen] = 0x93 ; MsgLen++ ;
		Msg[MsgLen] = 0x9e ; MsgLen++ ;
		//Acknowledgement number (relative ack number)
		Msg[MsgLen] = 0x50 ; MsgLen++ ;
		Msg[MsgLen] = 0xaa ; MsgLen++ ;
		Msg[MsgLen] = 0xcb ; MsgLen++ ;
		Msg[MsgLen] = 0x6a ; MsgLen++ ;
		//Header length: 20 bytes
		Msg[MsgLen] = 0x50 ; MsgLen++ ;
		//Flags: 0x18 (PSH, ACK)
		Msg[MsgLen] = 0x18 ; MsgLen++ ;
		//Window size: 65494
		MsgLen += LongToChar( 65494 , Msg+MsgLen , 2 ) ;
		//Checksum: 0x1941 [validation disabled]
		Msg[MsgLen] = 0x19 ; MsgLen++ ;
		Msg[MsgLen] = 0x41 ; MsgLen++ ;
		//Fill packet
		Msg[MsgLen] = 0x00 ; MsgLen++ ;
		Msg[MsgLen] = 0x00 ; MsgLen++ ;	
		
		/*Post Office Protocol*/
		if( strlen(PacketContent) > 0 ) MsgLen += ContentToChar( PacketContent , Msg+MsgLen ) ;
  		
		/*change total length */		
	  LongToChar( MsgLen-14 , Msg+16 , 2 ) ;	
  	
		// read msg
		printf(" MsgLen: %d\n", MsgLen);
		for( int d =0 ;d<MsgLen; d++ )
		{
			if( d!=0 && d%8 == 0 ) printf("\n") ;
			printf(" 0x%.2x ,",Msg[d]);
		}
		printf("\n========================================================\n");
		
		sendPcap( dev , Msg , MsgLen , RepeatNum , Interval ) ;
		printf( "==========================  END %s  ==========================\n\n" , itemName);
	}

}

void sendPcap( char * dev , u_char * msg , int msgLen , int repeatNum , int interval )
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;
	const u_char *packet;
	struct pcap_pkthdr hdr;     /* pcap.h                    */
	struct ether_header *eptr;  /* net/ethernet.h            */
	struct bpf_program fp;      /* hold compiled program     */
	bpf_u_int32 maskp;          /* subnet mask               */
	bpf_u_int32 netp;           /* ip                        */
	
	
	/* ask pcap for the network address and mask of the device */
	pcap_lookupnet(dev,&netp,&maskp,errbuf);
	/* open device for reading this time lets set it in promiscuous */
	/* mode so we can monitor traffic to another machine */
	descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
	if(descr == NULL)
	{
		printf("pcap_open_live(): %s\n",errbuf);
		return ;
	}
	/* Lets try and compile the program.. non-optimized */
	if(pcap_compile(descr,&fp,"tcp",0,netp) == -1)
	{
		fprintf(stderr,"Error calling pcap_compile\n");
		return ;	
	}	
	/* set the compiled program as the filter */
	if(pcap_setfilter(descr,&fp) == -1)
	{
		fprintf(stderr,"Error setting filter\n");
		return  ;
	}
	
	for(int i = 0; i<repeatNum ; i++)
	{
		printf("Info: sendPcap ==> %d / %d \n" , i+1 , repeatNum ) ;
		pcap_sendpacket(descr, msg , msgLen ) ;
		if( i<repeatNum-1 &&  interval > 0 ) usleep(interval*1000) ;
	}
	
	

}

int HexStringToChar( char * string , u_char * rst)
{
	char temp[5] ;
	int ind = 0 ;
	int i = 0 ;
	int ind_rst = 0 ;
	while( string[ind] != '\0' )
	{
		bzero(temp,sizeof(temp)) ;
		i=0 ;
		while( string[ind] != ' ' &&  string[ind] != '\0' )
		{
			temp[i++] = string[ind++] ;
		}
		if( string[ind] == ' ' ) ind++ ;
		temp[i]='\0' ;
		if(strlen(temp) == 0 ) continue ;
		rst[ind_rst]=HexToChar(temp,strlen(temp) );
		ind_rst++ ;
	}
	return ind_rst ;
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

int LongToChar( long num , u_char * rst , const int len_rst )
{
	int ind_rst = 0 ;
	u_char temp[len_rst] ;
	bzero(temp,len_rst) ;
	long tnum = num ;
	for( int i = len_rst-1 ; i >=0 && tnum > 0 ; i-- )
	{
		temp[i] = tnum & 0xFF ;
		tnum = tnum >> 8 ;
	}
	for( int i = 0 ; i<len_rst ; i++ )
	{
		rst[i]=temp[i] ;
	}
	return len_rst ;
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

int ContentToChar( char * content , u_char * rst) 
{
	int ind_rst = 0 ;
	for( int ind = 0 ; ind<strlen(content) ; ind++ )
	{
		if( content[ind] == '\\' )
		{
			ind++ ;
			switch( content[ind] )
			{
			case 't':
				rst[ind_rst++] = '\t' ;
				break ;
			case 'r':
				rst[ind_rst++] = '\r' ;
				break ;
			case 'n':
				rst[ind_rst++] = '\n' ;
				break ;
			case ' ':
				rst[ind_rst++] = ' ' ;
				break ;
			defualt :
				rst[ind_rst++] = '\\' ;
				rst[ind_rst++] = content[ind] ;
				break ;
			}
		}
		else
		{
			rst[ind_rst++] = content[ind] ;
		}
	}
	return ind_rst ; 
}
