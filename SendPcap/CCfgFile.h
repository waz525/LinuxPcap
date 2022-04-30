#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STRLEN 1000
struct CFG_LINK
{
        char * item ;
        char * field ;
        char * value ;
        struct CFG_LINK * next ;
} ;

class CCfgFile
{
	public :
		CCfgFile();
//		CCfgFile( char * FileName );
		CCfgFile( char * FileName , int haveItem ); //default: haveItem = 1 
		~CCfgFile();

		int GetFlagLoad();
		void LoadFile(char * FileName , int haveItem ); //load another configure file ( default: haveItem = 1 )
		char * QueryValue(char * item , char * field);//query value of a field
		char * QueryValueNoItem(char * field);//query value of a field with no item 
		void GetValue(char*, char*, char*);
		void GetValue(char*, char*, char*, char* );
		int GetValueInt(char * item , char * field , int defualt );
		void ShowCfg();// print value of all fields 

	private :
		struct CFG_LINK * head ;
		struct CFG_LINK * p ;
		struct CFG_LINK * q ;
		int flag_load; // 1: load file success ; 0: no file load
		int isHaveItem ; // 1:(default) have item ; 0: no item

		void AnalyseFile(char * FileName);
		void AnalyseString(char * string);
		void ReleaseLink();

} ;
