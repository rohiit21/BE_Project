from Tools.clickjack.clickjack import *
from Tools.xss.xss import *
from Tools.ssl_check.ssl import ssl_check
from Tools.xss.util.checker import *
from Tools.xss.util.parameterCrawl import *
from Tools.xss.util.urlparser import *
from Tools.xss.core import requester
from Tools.sqlinjection.sql2 import sql_injection_scanner
from Tools.openredirect.openredirect_3 import open_redirect_abc
from Tools.security_header.security_header import security_header_main
from Tools.mailMisconfig.Mail_Mis_Config import mail_mis_config



def clickjacking(domain_name):
    url="http://"+domain_name
    parse_url = urlparse(url)
    domain=parse_url.netloc
    if domain.startswith('www.'):
        domain_name = domain[4:]
    print(domain_name)
    status=clickjack_Check(domain_name)
    return status


def mailmisconfig(domain_name):
    mmcf_data= mail_mis_config(domain_name)
    print(mmcf_data)
    return mmcf_data


def sslcheck(domain_name):
    cert_info=ssl_check(domain_name)  
    return cert_info
    


def XSS(domain_name):
    xss_vulnerable_urls=check_XSS(domain_name)
    return xss_vulnerable_urls


def Open_Redirect_Script(domain_name):
    openredirect_vulnerable_urls=open_redirect_abc(domain_name)
    print("Hii")
    print(openredirect_vulnerable_urls)
    y=len(openredirect_vulnerable_urls)
    return openredirect_vulnerable_urls


def Security_Header_Scanner(domain_name):
    url="http://"+domain_name
    try:
        data_information=security_header_main(url)
    except Exception as e:
        data_information={'X-XSS-Protection' : False,'X-Content-Type-Options' : False,'X-Frame-Options ' : False,'Strict-Transport-Security' : False, 'Content-Security-Policy' : False}
    return data_information



def SqlInjection(domain_name):
    sql_vulnerable_urls=sql_injection_scanner(domain_name)
    y=len(sql_vulnerable_urls)
    return sql_vulnerable_urls

def single_scanner(domain_name,vulnerability_name):
    if(vulnerability_name=="Clickjacking"):
        data=clickjacking(domain_name)
    elif(vulnerability_name=="mail_misconfiguration"):
        data=mailmisconfig(domain_name)
    elif(vulnerability_name=="SSL"):
        data=sslcheck(domain_name)
    elif(vulnerability_name=="XSS"):
        data=XSS(domain_name)
    elif(vulnerability_name=="Open_Redirect"):
        data=Open_Redirect_Script(domain_name)
    elif(vulnerability_name=="Security_Header"):
        data=Security_Header_Scanner(domain_name)
    elif(vulnerability_name=="SQL"):
        data=SqlInjection(domain_name)

    return data


# single_scanner("www.testphp.vulnweb.com","SQL injection","test","friday")

