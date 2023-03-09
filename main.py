from flask import *
from db import *
import os
from db import *
import mysql.connector
from datetime import datetime
from scanner import scanner
from singlescan import single_scanner
import regex as re


app  = Flask(__name__)
app.secret_key = os.urandom(24)


# start button page
@app.route('/Weber/', methods=['GET', 'POST'])
def welcome():
    return render_template('welcome.html')


@app.before_request
def before_request():
    if 'User_id' in session:
        g.user = session['user']
    else:
        g.user = None

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

# on button click (from above page) login page
@app.route('/Weber/Login', methods=['GET', 'POST'])
def login():
    return render_template('Login.html')


# Validate the login
# check if the user exists
# if the use exists redirect to the corresponding dashboard page
# if don't exist
@app.route('/Weber/Login/validate', methods=['GET', 'POST'])
def validate():
    try:
        if request.method == 'POST':
            session.pop('UserID',None)
            session.pop('user',None)
            email = request.form.get('email')
            password = request.form.get('password')
            #connect to database
            db_Name = "credential"
            conn = connectDB(db_Name)
            db = conn.cursor()
            try:
                db.execute('SELECT id,userName,email,password FROM users WHERE email = %(email)s AND password=%(password)s', { 'email' : email, 'password' :password })
                check =db.fetchone()
                # print(check)
                if check != None :
                    check = list(check)
                    flash('Succesfully logged in !!', 'Success')
                    session['UserID'] = check[0]
                    session['user'] = check[1]
                    return redirect(url_for('dashboard'))
                else:
                    flash('Wrong Email or password !! Enter valid Email and password', 'Error')
                    return redirect(url_for('login'))

            except:
                print("Failed to validate the user")                
            conn.close()
    except ConnectionError as err:
        print(err)


@app.route('/Weber/login/dashboard', methods=['GET', 'POST'])
def dashboard():
    
    id = session['UserID']
    user = session['user']

    # connect to the database to fecth the target list data
    conn = connectDB('credential')
    db = conn.cursor()

    
    table_name = "user_"+str(id)+"_"+str(user)+"_targetDetails"
            
    # table_name = "user_"+str(userID)+"_"+str(userName)+"_targetDetails"
    db.execute("show tables")
    lst = db.fetchall()
    # check if table already exist if not exist create one
    sql = "CREATE TABLE %s (address VARCHAR(255) UNIQUE KEY DEFAULT NULL, description VARCHAR(255)  DEFAULT NULL, severity VARCHAR(255) DEFAULT NULL)"% (table_name)
    if not table_name in lst:
        try:
            db.execute(sql)
        except:
            pass
    
    db.execute("SELECT * FROM {}".format(table_name))
    lst = db.fetchall() # fecthing all the data
    # converting the tuples inside the list into the list data format
    for i in range(len(lst)):
        lst[i] = list(lst[i])
    # print(lst)
    # pass the data to the html file
    return render_template('dashboard.html',user=user, data=lst)

# 43ndering the remplate for add target page
@app.route('/Weber/login/addTarget')
def Target():
    user =session['user']
    return render_template('addTarget.html', user=user)

# When user click on the add target button
# the details will be fetched here
@app.route('/Weber/login/Target', methods=['GET', 'POST'])
def addTarget():
    if request.method == 'POST':
        target = request.form.get('address')
        desc = request.form.get('description')
        if len(target)==0 or len(desc)==0:
            flash('Please add both Domain Name and Domain Description', 'Error')
            return redirect(url_for('addTarget'))
        else:
            regex="^www.[-a-zA-Z0-9@:%._\\+~#?&//=]{2,256}\\.[a-z]{2,6}\\b([-a-zA-Z0-9@:%._\\+~#?&//=]*)$"
            r = re.compile(regex)
            if not re.search(r, target):
                flash('Please add both Domain Name and Domain Description', 'Error')
                return redirect(url_for('addTarget'))


        severity = None
        userID = session['UserID'] # fetching the current user id
        userName = session['user'] # fetching the current user username
        
        conn = connectDB('credential') # connecting to the database 
        db = conn.cursor() # database object
        # table name
        table_name = "user_"+str(userID)+"_"+str(userName)+"_targetDetails"
        db.execute("show tables")
        lst = db.fetchall()
        # check if table already exist if not exist create one
        sql = "CREATE TABLE %s (address VARCHAR(255) UNIQUE KEY DEFAULT NULL, description VARCHAR(255)  DEFAULT NULL, severity VARCHAR(255) DEFAULT NULL)"% (table_name)
        if not table_name in lst:
            try:
                db.execute(sql)
            except:
                pass

        # add details to table
        try:
            insert_sql = "INSERT INTO {} (address, description, severity) VALUES (%s, %s, %s)".format(table_name)
            val = (target, desc, severity)
            db.execute(insert_sql, val)
            conn.commit()
            conn.close()
            flash('Target added successfully', 'Success')
        except mysql.connector.errors.ProgrammingError as err:
            print(err)

        return redirect(url_for('Target'))
    else:
        return redirect(url_for('Target'))
    

@app.route('/Weber/login/targetlist')
def targetlist():
    userID = session['UserID'] # fetching the current user id
    user = session['user']
    conn = connectDB('credential') # connecting to the database 
    db = conn.cursor() # database object
    table_name = "user_"+str(userID)+"_"+str(user)+"_targetDetails"
    try:
        insert_sql = "SELECT * FROM {}".format(table_name)
        db.execute(insert_sql)
        lst = db.fetchall()
        conn.commit()
        conn.close()
    except mysql.connector.errors.ProgrammingError as err:
        print(err)


    
    for i in range(len(lst)):
        lst[i] = list(lst[i])


    
    return render_template('TargetList.html', user=user, data=lst)


@app.route('/Weber/login/report', methods=['GET', 'POST'])
def scan():
    userName = session['user']
    conn = connectDB('vulndescription') # connecting to the database 
    db = conn.cursor()
    table_name = "found_vuldetails"


    if request.method == 'POST':
        if request.form.get('report') == 'Report':
            DomainName = request.form['url']
            DomainDesc = request.form['url1']
            DomainTime = request.form['url2']
        

        else:
            pass
    elif request.method == 'GET':
        pass



    try:
        insert_sql = "SELECT data FROM {} where User_name='{}' and domain_name='{}' and last_time='{}'".format(table_name,userName,DomainName,DomainTime)
        print(insert_sql)
        db.execute(insert_sql)
        lst = db.fetchall()
        print(lst)
        conn.commit()
        conn.close()
    except mysql.connector.errors.ProgrammingError as err:
        print(err)

    data = json.loads(lst[0][0])
    print(data)


    if not data:
        flash('No Record Found First Scan', 'Error')
        return redirect(url_for('reportList'))

         
    else:    
        flash('Report Fetched Successfully', 'Success')
        return render_template("report.html",data=data,user=userName,DomainName=DomainName,DomainDesc=DomainDesc,DomainTime=DomainTime)
    



@app.route('/Weber/login/reportList')
def reportList():
    userID = session['UserID'] # fetching the current user id
    user = session['user']
    conn = connectDB('vulndescription') # connecting to the database 
    db = conn.cursor() # database object
    table_name = "found_vuldetails"
    try:
        insert_sql = "SELECT domain_name,domain_desc,data,last_time FROM {} where User_name='{}' ".format(table_name,user)
        print(insert_sql)
        db.execute(insert_sql)
        lst = db.fetchall()
        print(lst)
        conn.commit()
        conn.close()
    except mysql.connector.errors.ProgrammingError as err:
        print(err)
    
    for i in range(len(lst)):
        lst[i] = list(lst[i])


    return render_template('ReportList.html' ,data=lst)



@app.route('/Weber/login/scan')
def scanpage():
    # user = session['user']
    return render_template("scanning.html")


@app.route('/Weber/login/resources')
def resources():
    user = session['user']
    return render_template("resources.html",user=user)

@app.route('/logout')
def logout():
    session.pop('UserID', None)
    session.pop('user')
    flash('Succesfully logged out', 'success')
    return redirect(url_for('login'))

@app.route('/Weber/login/about')
def about():
    # user = session['user']
    return render_template("about.html")


@app.route("/scanningforvuln/", methods=['GET', 'POST'])
def index():
    userID = session['UserID'] # fetching the current user id
    user = session['user']
    conn = connectDB('credential') # connecting to the database 
    db = conn.cursor() # database object
    table_name = "user_"+str(userID)+"_"+str(user)+"_targetDetails"
    try:
        insert_sql = "SELECT * FROM {}".format(table_name)
        db.execute(insert_sql)
        lst = db.fetchall()
        conn.commit()
        conn.close()
    except mysql.connector.errors.ProgrammingError as err:
        print(err)

    
    for i in range(len(lst)):
        lst[i] = list(lst[i])
    if request.method == 'POST':
        if request.form.get('scan') == 'Scan':
            data = request.form['url']
            domaindesc= request.form['url1']
            print(data)
            now = datetime.now()
            current_time = now.strftime("%d/%m/%Y %H:%M:%S")
            try :
                scanner(data,domaindesc, user , current_time)
                flash('Scan Completed !!', 'Success')
            except:
                flash('Scan Interrupted!!', 'Failed')
        else:
            pass
    elif request.method == 'GET':
        pass
    return redirect(url_for('targetlist'))
    # return render_template("TargetList.html",data=lst)



@app.route('/Weber/login/singleScan')
def singlescan():
    user =session['user']
    return render_template('singleScan.html', user=user)



@app.route('/Weber/login/singlescan', methods=['GET', 'POST'])
def single_scan_fun():
    if request.method == 'POST':
        target = request.form.get('address')
        vuln_name = request.form.get('vulns')
        print(target)
        print(vuln_name)
        if len(target)==0 or len(vuln_name)==0:
            flash('Please add both domain and Vulnerability name to be checked !!', 'Error')
            return redirect(url_for('singlescan'))
    
        data=single_scanner(target,vuln_name)
        print(data)
        return render_template('singleScanResult.html',target=target,data=data,vuln_name=vuln_name)
        

if __name__ == '__main__':
    app.run(debug=True)