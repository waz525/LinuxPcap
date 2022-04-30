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

char dev[10] ;
char filter[1000] ;
char capfile[100] ;
int wFlag ;
int count ;
int promisc ;
int detil ;

void err_sys(const char *errmsg) ;
void ShowVersion( char * version ) ;
void ShowHelp( char * pro_name) ;
void CatchPacket() ;
void ReadFromFile();

void AnalysePacket( struct pcap_pkthdr *m_headerPtr , const u_char *m_dataPtr ) ;
void ShowPacketDetil(const u_char * data , int len ) ;
void HexToString(const unsigned char * oldString , int length , char * newString ) ;
int HexToString(const unsigned char hexChar , char * newString ) ;
int HexToChar(const unsigned char hexChar , char * newchar ) ;
void HexToMAC(const unsigned char * hexChar , char * newString ) ;
void HexToIP(const unsigned char * hexChar , char * newString ) ;
long HexToLong( const unsigned char * hexChar , int len ) ;

