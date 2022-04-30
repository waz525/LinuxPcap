#include "SearchPcap.h"

int main( int argc , char ** argv )
{
	int ch ;
	int flag = 0 ;
	type = 0 ;
	mStart = 0 ;
	mCount = 0;
	char types[50] ;
	if( argc > 1 )
	{
		while((ch = getopt(argc,argv,"r:t:k:s:c:w:vVhH*"))!= -1)
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
				strcpy(pcapFile , optarg);
				flag |= 1<<0 ;
				break ;
			case 't':
				strcpy(types , optarg);
				flag |= 1<<1 ;
				break ;
			case 'k':
				strcpy(keyword , optarg);
				flag |= 1<<2 ;
				break ;
			case 'w':
				strcpy(newFile , optarg);
				flag |= 1<<3 ;
				break ;	
			case 's':
				mStart =  atoi(optarg);
				flag |= 1<<4 ;
				break ;	
			case 'c':
				mCount =  atoi(optarg);
				flag |= 1<<5 ;
				break ;
			}
		}
	}
	
//	printf("%s ---> %d --- %x\n" , types , type , type );
	
		
	if( flag != 7 && flag != 59 ) 
	{
		ShowHelp( argv[0] ) ;
		return 0 ;
	}
	
	if( strcmp(types , "SearchByKeyword") == 0 ) 
	{
		type |= 1<<0 ;
	}
	else if( strcmp(types , "GetPacpByIndex") == 0 ) 
	{
		type |= 1<<1 ;
	}
	else
	{
		printf("ERROR: type(%s) is not support , run '%s -h' to get help !!!\n" , types , argv[0] ) ;
		return 0 ;
	}
	//printf("INFO: Change %s : %s --> %s ( %s --> %s )\n",types,oldfile,newfile,oldpara,newpara);

	
	return SearchPcap() ;
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
	printf("Usage: %s -r PcapFile -t SearchByKeyword -k KeyWords\n",pro_name);
	printf("Usage: %s -r PcapFile -t GetPacpByIndex -s start -c count -w newPcapFile\n",pro_name);

}

int SearchPcap()
{
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	struct pcap_pkthdr *m_headerPtr;
	const u_char *m_dataPtr ;
	u_char * dataPtr ;
	
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
	int matchCount = 0 ;
	
	if( ( type& 1<<0) > 0 )
	{
		printf( "INFO: Begin to search \"%s\" in %s ...\n" , keyword , pcapFile ) ;
		while(pcap_next_ex(adhandle, &m_headerPtr, &m_dataPtr)>0)
		{
			index++ ;	
			if( BinaryMatch( m_dataPtr , m_headerPtr->caplen , keyword , strlen(keyword) ) != -1 )
			{
				matchCount++ ;
				printf( "MATCH[%d]: Match keyword(%s) index is %d ...\n" , matchCount , keyword , index  ) ;
			}
		}
		printf( "INFO: SearchByKeyword OVER , total count is %d , matched %d !!!\n" , index , matchCount ) ;
	}
	
	if( ( type& 1<<1) > 0 )
	{
		pcap_dumper_t *dumpfile;
		dumpfile=pcap_dump_open(adhandle,newFile);
		printf( "INFO: Begin to get pacp from %s[%d:%d] to %s ...\n" , pcapFile , mStart , mCount , newFile) ;
		while(pcap_next_ex(adhandle, &m_headerPtr, &m_dataPtr)>0)
		{
			index++ ;
			if( (index >= mStart) && (index - mStart < mCount ) )
				pcap_dump((u_char*)dumpfile , m_headerPtr, m_dataPtr) ;
			if( index - mStart == mCount ) break ;
		}
		printf( "INFO: GetPacpByIndex OVER !!!\n" , pcapFile  ) ;
	}
	
	return 0 ;
}


int BinaryMatch( const u_char * haystack , const int len_haystack ,  const char * needle , const int len_needle )
{
	int res = -1 ; 
	int i = 0 ;
	int j = 0 ; 
//	printf( "1: %d --> %d \n" , len_haystack , len_needle ) ;
	while( i < len_haystack && j < len_needle ) 
	{
		if( haystack[i+j] == needle[j] )
		{
			j++ ;
		}
		else if( j == 0 ) 
		{
			i++ ;
		}
		else
		{
			i++ ;
			j = 0  ;
		}
	}
	
//	printf( "2: %d --> %d \n" , i , j ) ;
	if( i < len_haystack ) res = i ; 
//	printf( "3: %d : %d \n\n", i , res ) ;
	return res ;
}
