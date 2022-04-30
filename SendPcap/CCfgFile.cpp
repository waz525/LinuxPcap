#include "CCfgFile.h"

CCfgFile::CCfgFile()
{
        head=NULL ;
        p=NULL ;
        q=NULL ;
        flag_load=0 ;
	isHaveItem=1;
}
/*
CCfgFile::CCfgFile(char * FileName)
{
	head=NULL ;
	p=NULL ;
	q=NULL ;
	flag_load=0 ;
	isHaveItem=1;
	AnalyseFile(FileName);
}*/

CCfgFile::CCfgFile(char * FileName , int haveItem = 1 )
{
	head=NULL ;
	p=NULL ;
	q=NULL ;
	flag_load=0 ;
	isHaveItem=haveItem;
	AnalyseFile(FileName);
}


CCfgFile::~CCfgFile()
{
	ReleaseLink();
}

int CCfgFile::GetFlagLoad()
{
	return flag_load ;
}

void CCfgFile::AnalyseFile(char * FileName)
{
        char str[STRLEN];
        int i;
        char c ;
        FILE *fd ;
        fd=fopen(FileName,"r");
	if(fd==NULL)
	{
		return ;
	}
        c=fgetc(fd);
        i=0;
        q=(struct CFG_LINK *)malloc(sizeof(struct CFG_LINK));
        p=q;
        head=q;
        while(c!=EOF)
        {
                if(c=='\t' || c == ';')
                {
                        c=fgetc(fd);
                        continue ;
                }
                if(c=='\n')
                {
                        str[i]='\0';
                        AnalyseString(str);
                        i=0;
                        c=fgetc(fd);
                        continue ;
                }
                str[i++]=c;
                c=fgetc(fd);
        }
        p->next=NULL;
        free(q);
        q=head;
	flag_load=1;
}

void CCfgFile::AnalyseString(char * string)
{
        int i , j , f;
        char str[STRLEN];
        char * ch;
        strcpy(str,string);
        for(i=0;i<strlen(str);i++)
        {
                if(str[i]=='#')
                        str[i]='\0';
                if(str[i]=='/' && str[i+1]=='/')
                        str[i]='\0';
        }
	for( i = 0 , f=1; str[i] != '\0' ;  )
	{
		if( str[i] == ' ' && f%2 == 1 )
		{
			for( j = i ; str[j] != '\0' ; j++ )
				str[j] = str[j+1] ;
		}
		else
		{
			if( str[i] == '"' && str[i-1] != '\\' ) f++ ;
			i++ ;
		}
	}
	if(strlen(str)==0) return ;
	if(isHaveItem)
	{
	        if(str[0]=='[')
	        {
        	        q->item = (char *)malloc(strlen(str));
        	        for(i=1;i<strlen(str);i++)
	                {
	                        if(str[i]==']')
	                        {
	                                q->item[i-1]='\0';
	                                break ;
	                        }
	                        
	                        q->item[i-1]=str[i];
	                }
	                return ;
        	}
	        else
	        {
	    		if( ! q->item )
        	        	q->item = (char *)malloc(strlen(p->item));
        	        if(strlen(q->item)==0)
        	        {
                	        strcpy(q->item,p->item);
                	}
	        }
	}
	else
	{
		q->item = (char *)malloc(5);
		strcpy(q->item,"");	
	}
        if(p!=q)
                p=p->next;
        ch=strchr(str,'=');
        p->value = (char *)malloc(strlen(str));
        strcpy(p->value,ch+1);
	for(i=0 ; p->value[i] != '\0' ; )
	{
		if( p->value[i] == '"' )
		{
			for( j = i ; p->value[j] != '\0' ; j++ ) p->value[j] = p->value[j+1] ;
		}
		else
		{
			i++ ;
		}
	}
	j=strlen(str) - strlen(p->value) +10; 
	 p->field = (char *)malloc(j);
        for(i=0;i<strlen(str);i++)
        {
                if(str[i]=='=')
                {
                        p->field[i]='\0';
                        break ;
                }
                p->field[i]=str[i];
        }
        q=(struct CFG_LINK *)malloc(sizeof(struct CFG_LINK));
        p->next=q;
}

void CCfgFile::ReleaseLink()
{

	while(head->next!=NULL)
	{
		for(p=head,q=head;p->next!=NULL;p=p->next)
		{
			q=p;
		}
		q->next=NULL;
		free(p);
	}
	free(head);
	head=NULL;
	p=NULL;
	q=NULL;
	flag_load=0;
}

void CCfgFile::LoadFile(char * FileName , int haveItem=1 )
{
	ReleaseLink();
	isHaveItem=haveItem;
	AnalyseFile(FileName);
}

void CCfgFile::ShowCfg()
{
	if( flag_load == 1 )
	{
	        for( p=head ; p!=NULL ; p=p->next )
        	{
			if(isHaveItem)
			{
	                	printf("%s : %s = %s \n",p->item,p->field,p->value);
			}
			else
			{
				 printf("%s = %s \n",p->field,p->value);
			}
	        }
	}
	else
	{
		printf("Config file is not open ! ShowCfg can't work !\n") ;
		return ;
	}
}

char * CCfgFile::QueryValue(char * item , char * field)
{
	if( flag_load == 1 )
	{
	        for( p=head ; p!=NULL ; p=p->next )
	        {
	                if( strcmp(p->item , item) == 0 )
	                {
	                        if( strcmp(p->field , field) == 0 )
	                                return p->value ;
	                }
	        }
	        return "no such field" ;
	}
	else
	{
		//printf("Config file is not open ! QueryValue can't work !\n") ;
		return "" ;
	}
}

void CCfgFile::GetValue(char * item , char * field , char * rst )
{
	strcpy( rst , "no such field" ) ;
	if( flag_load == 1 )
	{
		for( p=head ; p!=NULL ; p=p->next )
		{
			if( strcmp(p->item , item) == 0 )
			{
				if( strcmp(p->field , field) == 0 )
					strcpy( rst ,  p->value ) ;
			}
		}
	}

}

void CCfgFile::GetValue(char * item , char * field , char * rst , char * defualt )
{
	strcpy( rst , defualt ) ;
	if( flag_load == 1 )
	{
		for( p=head ; p!=NULL ; p=p->next )
		{
			if( strcmp(p->item , item) == 0 )
			{
				if( strcmp(p->field , field) == 0 ) strcpy( rst ,  p->value ) ;
			}
		}
	}
}

int CCfgFile::GetValueInt(char * item , char * field , int defualt )
{
	char rst[10] ;
	char str[10] ; 

	sprintf( str , "%d" , defualt ) ;
	GetValue( item , field , rst , str ) ;
	return atoi(rst) ;

}

char * CCfgFile::QueryValueNoItem(char * field)
{
	return QueryValue("",field);
}
