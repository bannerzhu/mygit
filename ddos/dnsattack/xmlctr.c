/********************************************************************************/
/* ��ȡxml�����ļ���������                                                      */
/* author:cp                                                                    */
/* 2008.3.20                                                                    */
/* change:2009.11.25                                                            */
/********************************************************************************/
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 

#include "xmlctr.h"

/*
 * init xmlcnf
 * return:
 *         -1 fail
 *         0  success
 */
int xmlcnf_init(char *cnfname,s_xmlcnf *xmlcnf)
{
    if(!cnfname || strlen(cnfname)>STR_BUF_LEN || !xmlcnf)
        return -1;   
    strcpy(xmlcnf->cnfname,cnfname);
    xmlcnf->doc = xmlParseFile(xmlcnf->cnfname);
	if( !xmlcnf->doc )
	{
		fprintf(stderr,"[ERROR] xmlcof parse failed\n");
		return -1;
	}
	
	xmlcnf->cur = xmlDocGetRootElement(xmlcnf->doc);
	if( !xmlcnf->cur )
	{
		fprintf(stderr,"[ERROR] xmlconf is empty\n");
		xmlFreeDoc(xmlcnf->doc);
		return -1;
	}
	return 0;
}

/*
 * ��ת����һ�ڵ�/�ӽڵ�
 * params:
 *        nodelevel �ڵ�㼶 (0/1 ͬ���ڵ�/�Ӽ��ڵ�)
 */
void xmlcnf_node_next(s_xmlcnf *xmlcnf,char nodelevel)
{
    if(nodelevel)
        xmlcnf->cur = xmlcnf->cur->xmlChildrenNode;
    else
        xmlcnf->cur = xmlcnf->cur->next;
}

/*
 * �ͷ���Դ
 *
 */
int xmlcnf_free(s_xmlcnf *xmlcnf)
{
    if(!xmlcnf)
        return -1;
    if(xmlcnf->doc)
        xmlFreeDoc(xmlcnf->doc);
	xmlCleanupParser();
	return 0;
}

/*
 * �Ƚ�xmlChar�ַ�����char�ַ���
 * return:
 *        0  equal
 *        ~0 different
 */
int xmlcnf_strcmp(xmlChar *strx,char *str)
{
    return xmlStrcmp(strx,BAD_CAST(str));
}

/*
 * ��鵱ǰ�ڵ������Ƿ�Ϊ��Ҫ��
 * return:
 *        0    equal
 *        ~0   different
 */
int xmlcnf_node_check(s_xmlcnf xmlcnf,char *node_name)
{
    return xmlStrcmp(xmlcnf.cur->name,(const xmlChar *)node_name);
}

/*
 * ��ȡ��ǰ�ڵ�����ֵ,��ŵ�����buff��
 * return:
 *         0  success
 *         ~0 fail
 */
int xmlcnf_node_getattribute(s_xmlcnf xmlcnf,char *attributename,char *buff)
{
    xmlChar *temp;
    temp = xmlGetProp(xmlcnf.cur,BAD_CAST(attributename));
    if(!temp)
        return -1;
    //printf("--[%s]\n",temp);
    strcpy(buff,(char *)temp);
    xmlFree(temp);
    return 0;
}

/*
 * ��ȡ��ǰ�ڵ�ֵ,��ŵ�����buff��
 * return:
 *         0  success
 *         ~0 fail
 */
int xmlcnf_node_getvalue(s_xmlcnf xmlcnf,char *nodename,char *buff)
{
    xmlChar *temp=NULL;
    if( !xmlcnf_node_check(xmlcnf,nodename) )
    {
        temp = xmlNodeListGetString(xmlcnf.doc,xmlcnf.cur->xmlChildrenNode,1);
        if(!temp)
            return -1;
        strcpy(buff,(char *)temp);
        xmlFree(temp);
        return 0;
    }
    return -1;
}

