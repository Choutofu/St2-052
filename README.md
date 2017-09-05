
# St2-052 远程代码命令执行漏洞预警(CVE-2017-9805)

描述：当使用带有XStream处理程序的Struts REST插件来反序列化XML请求时，可能会发生RCE攻击 

CVE编号:CVE-2017-9805 

受影响的版本:Struts 2.5 - Struts 2.5.12

解决方法:升级到Apache Struts版本2.5.13，最好的选择是在不使用时删除Struts REST插件，或仅限于服务器普通页面和JSONs：

<constant name="struts.action.extension" value="xhtml,,json" />

由于应用的可用类的默认限制，某些REST操作可能会停止工作。在这种情况下，请调查介绍的新接口以允许每个操作定义类限制，那些接口是：
org.apache.struts2.rest.handler.AllowedClasses
org.apache.struts2.rest.handler.AllowedClassNames
org.apache.struts2.rest.handler.XStreamPermissionProvider

https://cwiki.apache.org/confluence/display/WW/S2-052
