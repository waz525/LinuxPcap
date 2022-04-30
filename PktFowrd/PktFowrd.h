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
#include <sys/time.h>
#include <netinet/if_ether.h>
#include <time.h>
#include <ctype.h>
#define LEN_ETHERNET 14

char pcapFile[1000] ;
char inInterface[100] ;
char outInterface[100] ;
int pcapIndex ;
int maxCount ;
char filterStr[1000] ;
char dMacStr[20] ;
int pps ;

void PktFowrdFile() ;
void PktFowrdInterface() ;
void SendPcap(pcap_t* descr , const u_char * m_dataPtr , int caplen) ;

int MacToChar( char * mac , u_char * rst) ;
long HexToChar(char * hex,int len);

void err_sys(const char *errmsg) ;
void ShowVersion( char * version ) ;
void ShowHelp( char * pro_name) ;

