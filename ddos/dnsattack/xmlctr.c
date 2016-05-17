/********************************************************************************/
/* 读取xml配置文件基础函数                                                      */
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
 * 跳转到下一节点/子节点
 * params:
 *        nodelevel 节点层级 (0/1 同级节点/子级节点)
 */
void xmlcnf_node_next(s_xmlcnf *xmlcnf,char nodelevel)
{
    if(nodelevel)
        xmlcnf->cur = xmlcnf->cur->xmlChildrenNode;
    else
        xmlcnf->cur = xmlcnf->cur->next;
}

/*
 * 释放资源
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
 * 比较xmlChar字符串与char字符串
 * return:
 *        0  equal
 *        ~0 different
 */
int xmlcnf_strcmp(xmlChar *strx,char *str)
{
    return xmlStrcmp(strx,BAD_CAST(str));
}

/*
 * 检查当前节点名称是否为需要的
 * return:
 *        0    equal
 *        ~0   different
 */
int xmlcnf_node_check(s_xmlcnf xmlcnf,char *node_name)
{
    return xmlStrcmp(xmlcnf.cur->name,(const xmlChar *)node_name);
}

/*
 * 获取当前节点属性值,存放到参数buff中
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
 * 获取当前节点值,存放到参数buff中
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

