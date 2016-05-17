dns_req 配置文件说明

该程序实现了udp或者tcp的dns请求攻击

对于udp可以伪造源ip 源端口
tcp要建立连接，不可伪造ip 端口

可伪造子级域名 ：
	在reqname参数中配置，如果level=0，则使用name中域名
			     如果level>1，则在name域名基础上伪造其子级域名，最多可伪造5级
			     伪造域名可在subLen中设置每级伪造的字符范围

对于tcp及心跳攻击未进行测试

