#include <pcap.h>
#include <pcap-bpf.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <ctype.h>

struct TCPDIALOG
{
	char IP1[20] ;
	char IP2[20] ;
	int Port1 ;
	int Port2 ;
	int pcapcount ;
	long len ;
	char * content ;
	struct TCPDIALOG *Next ;
	long long initSeqNum ;
	long long initAckNum ;
	int seqFlag  ;
};

typedef struct TCPDIALOG TCPDialog,*LPTCPDialog ;

LPTCPDialog pHeader ;
char pcapFile[1000] ;
int isDebugMode ;
int pcapIndex ;
int countDialog ; 
int maxDialog ;

int ParseTCP() ;
void ParseOnePcap(struct pcap_pkthdr *m_headerPtr , const u_char *m_dataPtr) ;
void HexToIP(const unsigned char * hexChar , char * newString );
long HexToLong( const unsigned char * hexChar , int len );
long long HexToLongLong(  const unsigned char * hexChar , int len ) ;
LPTCPDialog getDialogByIPPort(char * sip , int sport , char * dip , int dport ) ;
LPTCPDialog initTCPDialog() ;
void WriteTCPDialog() ;

void err_sys(const char *errmsg) ;
void ShowVersion( char * version ) ;
void ShowHelp( char * pro_name) ;

