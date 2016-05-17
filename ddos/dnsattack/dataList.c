/********************************************************************************/
/* 列表数据：链表存储                                                           */
/* author:cp                                                                    */
/* 2008.4.2                                                                     */
/********************************************************************************/
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <libxml/xmlmemory.h>
#include <libxml/parser.h>
#include <stdlib.h>
#include <time.h>

#include "dataList.h"
/********************************************************************************/
/*结构体dataList*/
dataList * newLink(int numtemp,char *datatemp)
{
	dataList *newOne;
	newOne = (struct dataList_st *)malloc(sizeof(struct dataList_st));
	newOne->num=numtemp;
	newOne->data=datatemp;
	newOne->next=NULL;
	return newOne;
}
/*destory link*/
void destoryLink(dataList * head)
{
	dataList *p,*q;
	p = head;
	while(p!=NULL){
		q = p;
		p=p->next;
		free(q);
	}
	head = NULL;
}

/*list string to list link*/
dataList * get_ls(char * datalsTemp)
{
	char *sep = ",";
	char *needSep = datalsTemp;
	dataList * head = NULL;
	dataList * current,* prev;
	int i=1;
	char * buf = strstr(needSep,sep);
	if(buf==NULL&&needSep[0]!=0){
		current=newLink(i,needSep);
		//printf("%d:%s\n",i,needSep);
		head = current;
	}
	else{
		while(buf!=NULL){
			buf[0]='\0';
			current=newLink(i,needSep);
			//printf("%d:%s\n",i,needSep);
			if(head==NULL){
				head = current;
				prev =head;
			}
			else{
				prev->next = current;
				prev = prev->next;
			}
			i++;
			needSep = buf+1;
			buf = strstr(needSep,sep);
		}
		if(buf==NULL&&needSep[0]!=0){
			current=newLink(i,needSep);
			//printf("%d:%s\n",i,needSep);
			prev->next = current;
			prev = prev->next;
		}
	}
	return head;
}

/*get link length*/
int getLinkLength(dataList * head)
{
	dataList *p;
	p = head;
	int i=0;
	while(p!=NULL){
		i++;
		p=p->next;
	}
	return i;
}

/*output list*/
void outputList(dataList * dataHead)
{
	dataList *p;
	p = dataHead;
	while(p!=NULL){
		printf("num:%d\n",p->num);
		printf("data:%s\n",p->data);
		p = p->next;
	}
}

/*get someone value*/
char * getSomeone(dataList * dataHead,int i)
{
	dataList *p;
	p = dataHead;
	int j;
	for(j=1;j<i;j++)
		p=p->next;
	return p->data;
}
/********************************************************************************/

/********************************************************************************/
datalist_arr * get_ls_arr(char * needSep)
{
	char *sep = ",";
	datalist_arr * dl_arr;
	dl_arr = (datalist_arr *)malloc(sizeof(datalist_arr));
	dl_arr->now_len=0;
	int i=0;
	//printf("-----------xmldate:%s\n",needSep);
	char * buf = strstr(needSep,sep);
	
	if(buf==NULL&&needSep[0]!=0){
		strcpy(dl_arr->data[i],needSep);
		dl_arr->now_len++;
	}
	else{
		while(buf!=NULL&&i<MAX_DATA_NUM)
		{
			buf[0]='\0';
			strcpy(dl_arr->data[i],needSep);
			dl_arr->now_len++;
			i++;
			needSep = buf+1;
			buf = strstr(needSep,sep);
		}
		if(buf==NULL&&needSep[0]!=0&&i<MAX_DATA_NUM){
			strcpy(dl_arr->data[i],needSep);
			dl_arr->now_len++;
		}
	}
	//outputList_arr(dl_arr);
	return dl_arr;
}
int getLinkLength_arr(datalist_arr * head)
{
	return head->now_len;
}
void outputList_arr(datalist_arr * dataHead)
{
	int i=0;
	while(i<dataHead->now_len)
	{
		printf("data:%s\n",dataHead->data[i]);
		i++;
	}
}
char * getSomeone_arr(datalist_arr * dataHead,int i)
{
	//printf("ooooooooo:%s\n",dataHead->data[i]);
	return dataHead->data[i];
}
/********************************************************************************/

int getRandomNumber(int num)
{
	int n;
	n = rand()%num+1;
	return n-1;
}

unsigned int getRandomNumberN(unsigned int a,unsigned int b)
{
    return (rand()%(b-a-1))+a;
    
}

