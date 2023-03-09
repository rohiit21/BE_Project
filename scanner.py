from Tools.clickjack.clickjack import *
from Tools.xss.xss import *
from Tools.ssl_check.ssl import ssl_check
from db import connectDB
import mysql.connector
from Tools.xss.util.checker import *
from Tools.xss.util.parameterCrawl import *
from Tools.xss.util.urlparser import *
from Tools.xss.core import requester
from Tools.sqlinjection.sql2 import sql_injection_scanner
from Tools.openredirect.openredirect_3 import open_redirect_abc
from Tools.security_header.security_header import security_header_main
from Tools.mailMisconfig.Mail_Mis_Config import mail_mis_config
import json
from datetime import datetime



def database(table_name):
    conn = connectDB('vulndescription')
    db = conn.cursor()

    db.execute("show tables")
    lst = db.fetchall()

    if not table_name in lst:
        try:
            sql = "CREATE TABLE %s (id INT AUTO_INCREMENT PRIMARY KEY, User_name VARCHAR(10) , domain_name LONGTEXT  DEFAULT NULL, domain_desc LONGTEXT  DEFAULT NULL,data JSON,last_time VARCHAR(50))"% (table_name)
            db.execute(sql)
        except :
            pass

    conn.close()

def clickjacking(domain_name):
    url="http://"+domain_name
    parse_url = urlparse(url)
    domain=parse_url.netloc
    if domain.startswith('www.'):
        domain_name = domain[4:]
    print(domain_name)
    status=clickjack_Check(domain_name)
    domain_name="www."+domain_name
    return status


def mailmisconfig(domain_name):
    mmcf_data= mail_mis_config(domain_name)
    print(mmcf_data)
    if mmcf_data:
        return mmcf_data



# def sslcheck(domain_name, table_name,user_name,current_time):
#     cert_info=ssl_check(domain_name)
#     # print(cert_info)
#     if cert_info:
#         return cert_info
    


def XSS(domain_name):
    xss_vulnerable_urls=check_XSS(domain_name)
    y=len(xss_vulnerable_urls)
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
    return sql_vulnerable_urls


    
def scanner(domain_name,domaindesc,user_name,current_time):
    table_name = "found_vulDetails"


    database(table_name) # create a table for user

    # check SSL certificate missing or expired 
    vuln1 = ssl_check(domain_name)

    # check for Security header
    vuln2 = Security_Header_Scanner(domain_name)

    # check if clickjacking
    vuln3 = clickjacking(domain_name)

    # check mail misconfiguration
    vuln4 = mailmisconfig(domain_name)

    # check if XSS
    vuln5 = XSS(domain_name)

    # check if SQL
    vuln6=SqlInjection(domain_name)

    # Check if Open Redirect
    vuln7 = Open_Redirect_Script(domain_name)


    vuln_data = {'SSL':vuln1, 'SecurityHeader':vuln2, 'clickjacking':vuln3, 'MailMisconfiguration':vuln4, 'XSS':vuln5, "sql":vuln6, "open redirect":vuln7}

    print(vuln_data)
    conn = connectDB('vulndescription')
    db = conn.cursor()

    json_vuln_data=json.dumps(vuln_data)
    print(type(json_vuln_data))
    try:
        insert_sql = "INSERT INTO {} (User_name, domain_name,domain_desc ,data,last_time) VALUES (%s,%s,%s,%s,%s)".format(table_name)
        val = (user_name, domain_name,domaindesc,json_vuln_data,current_time)
        db.execute(insert_sql, val)
        conn.commit()
        conn.close()

    except mysql.connector.errors.ProgrammingError as err:
        print(err)





