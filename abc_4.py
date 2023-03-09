# from flask import *
# from db import *
# import os

# import mysql.connector

# conn = connectDB('vulndescription') # connecting to the database 
# db = conn.cursor()

# table_name = "found_vuldetails"
# userName="test"
# DomainName="www.youtube.com"

# try:
#     insert_sql = "SELECT data FROM {} WHERE User_Id='{}' and domain_name='{}'".format(table_name,userName,DomainName)
#     db.execute(insert_sql)
#     lst = db.fetchall()
#     conn.commit()
#     conn.close()
# except mysql.connector.errors.ProgrammingError as err:
#     print(err)

# rohit_dict = {}
# for line1 in lst:
#     line1 = json.loads(line1[0])

#     # print(list(line1.keys())[0])
#     if(list(line1.keys())[0] == "Domain_name"):
#         rohit_dict['SSL'] = line1[list(line1.keys())[4]]
#     elif(list(line1.keys())[0] =="X-XSS-Protection"):
#         rohit_dict['Securityheader'] = line1
#     elif(list(line1.keys())[0] == "clickjacking"):
#         rohit_dict['clickjacking'] = line1['clickjacking']
#     elif(list(line1.keys())[0] == "MX_Records"):
#         rohit_dict['MailMisconfiguaration'] = line1
   
#     elif(list(line1.keys())[0] == '0'):
#         line1 = list(line1.values())
#         rohit_dict['XSS'] = line1
    

# print(rohit_dict)
# if not lst:
#     print("Hi")
# else:
#     print("No")


# abc=[('04/03/2023 21:35:15',)]

# str123 = ''.join(abc[0])

# print(str123)

# abc=[('www.testphp.vulnweb.com', '04/03/2023 21:35:15'),('www.pce.ac.in', '04/03/2024 21:35:19')]
# for row in abc:
#     print(row[0])
    # print(abc[0][1])
