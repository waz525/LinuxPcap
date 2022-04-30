#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>


#include "CCfgFile.h"

void SendPacket( char * cfgName );
void SendPacketByDetil( CCfgFile * m_cfgFile ) ;
void SendPacketByHexString( CCfgFile * m_cfgFile ) ;
void SendPacketByCapfile( CCfgFile * m_cfgFile ) ;
void ShowVersion( char * version );
void ShowHelp( char * pro_name);


long HexToChar(char * hex,int len);
int MacToChar( char * mac , u_char * rst) ;
int IPToChar( char * ip , u_char * rst );
int LongToChar( long num , u_char * rst , int len_rst ) ;
int ContentToChar( char * content , u_char * rst) ;
int HexStringToChar( char * string , u_char * rst) ;

void sendPcap( char * dev , u_char * msg , int msgLen , int repeatNum , int interval ) ;

