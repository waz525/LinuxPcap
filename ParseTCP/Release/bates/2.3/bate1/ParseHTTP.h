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
#include "ethertype.h"

struct TCPDialog
{
	char IP1[20] ;
	char IP2[20] ;
	int Port1 ;
	int Port2 ;
	long len ;
	char * content ;
	struct TCPDialog *Next ;
};

typedef struct TCPDialog HTTPDialog,*LPHTTPDialog ;

LPHTTPDialog pHeader ;
char pcapFile[1000] ;

int ParseHTTP() ;
int ParseOnePcap(struct pcap_pkthdr *m_headerPtr , const u_char *m_dataPtr) ;
void HexToIP(const unsigned char * hexChar , char * newString );
long HexToLong( const unsigned char * hexChar , int len );
LPHTTPDialog getDialogByIPPort(char * sip , int sport , char * dip , int dport ) ;
void WriteHTTPDialog() ;

void err_sys(const char *errmsg) ;
void ShowVersion( char * version ) ;
void ShowHelp( char * pro_name) ;

