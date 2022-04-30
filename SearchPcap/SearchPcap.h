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

char pcapFile[1000] ;
char newFile[1000] ;
char keyword[1000] ;
char filterStr[200];
int type ;
int mStart ;
int mCount ; 

int SearchPcap() ;
int BinaryMatch( const u_char * haystack , const int len_haystack ,  const u_char * needle , const int len_needle );
void HexToIP(const unsigned char * hexChar , char * newString );
long HexToLong( const unsigned char * hexChar , int len );
int FormatKeyword( char * keyword , int olen  , u_char* fkeyword);

void err_sys(const char *errmsg) ;
void ShowVersion( char * version ) ;
void ShowHelp( char * pro_name) ;
