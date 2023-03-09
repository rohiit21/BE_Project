import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from urllib.parse import * 
from Tools.sqlinjection.Crawler.parameterCrawl import crawl

vulnerable_urls_with_sqli=[]
parametered_url_list1=[]
s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"




def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    """
    This function extracts all possible useful information about an HTML `form`
    """
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its `response`"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
    
        if error in response.content.decode(encoding='latin1').lower():
            return True
    # no error detected
    return False


def scan_sql_injection(url):
    # test on URL
    for c in "\"'":
        # add quote/double quote character to the URL
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)
        # make the HTTP request
        res = s.get(new_url)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself, 
            # no need to preceed for extracting forms and submitting them
            vulnerable_urls_with_sqli.append(url)
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            f = open("vulnerable.txt", "a")
            f.write('SQL Injection detected on the URL itself---->'+url+'\n')
            f.close()
            # vulnerable_urls_with_sqli.append(new_url)
            return
    # test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            # the data body we want to submit
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    # any input form that has some value or hidden,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"
            # join the url with the action (form request URL)
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            # test whether the resulting page is vulnerable
            if is_vulnerable(res):
                print("[+] SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                vulnerable_urls_with_sqli.append(url)
                f = open("vulnerable.txt", "a")
                f.write('SQL Injection detected in the page---->'+url+'\n')
                f.close()
                break   
count=0
def sql_injection_scanner(domain_name):
    f = open("vulnerable.txt", "w")
    f.close()
    url =domain_name
   
    if url.startswith('www.'):
        url = url[4:]
    print(url)
    parametered_url_list = crawl(url)
    print(len(parametered_url_list))

    for urls in parametered_url_list:
        if urls.endswith('.css'):
            parametered_url_list.remove(urls)
        elif urls.endswith('.pdf'):
            parametered_url_list.remove(urls)
        elif urls.endswith('.xlsx'):
            parametered_url_list.remove(urls)
        elif urls.endswith('.jpg'):
            parametered_url_list.remove(urls)
        elif urls.endswith('.jpeg'):
            parametered_url_list.remove(urls)
        elif urls.endswith('.png'):
            parametered_url_list.remove(urls)
        elif urls.endswith('.gif'):
            parametered_url_list.remove(urls)
    
    for urls in parametered_url_list:
        if "?" not in urls:
            parametered_url_list.remove(urls)
 
    print(len(parametered_url_list))
    
  
    for i in range(100):
        try:
            scan_sql_injection(parametered_url_list[i])
        except ConnectionAbortedError:
            print("Failed to connect to the server")
        except:
            pass

    print(vulnerable_urls_with_sqli)
    return vulnerable_urls_with_sqli

# sql_injection_scanner("www.testphp.vulnweb.com")
