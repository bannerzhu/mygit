#ifndef _ATTACK_H_
#define _ATTACK_H_



#include "dnsattack_base.h"

struct attackM_st
{
	char *attackIp;
	char *attackPort;
	int pthread_id;
	ddosConfig *ddosc;
};

int newthread(struct attackM_st attackM);


/********************************************************************************/
/* ��ø��̷߳��Ͱ���֮��                                                       */
/* ����:�����ܺ�                                                                */
/********************************************************************************/
unsigned long getSendPackageNum(int startThreadNumber);

/********************************************************************************/
/* ��ø��̷߳���Byte֮��                                                       */
/* ����:����Byte�ܺ�                                                            */
/********************************************************************************/
unsigned long getSendByte(int startThreadNumber);

#endif

