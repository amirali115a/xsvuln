import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
import argparse
Gr='\033[1;32m'
Ye='\033[1;33m'
Wh='\033[1;37m'
print(f'''{Ye}

                       _       
                      | |      
 __  _______   ___   _| |_ __  
 \ \/ / __\ \ / / | | | | '_ \ 
  >  <\__ \\ V /| |_| | | | | |
 /_/\_\___/ \_/  \__,_|_|_| |_|
                               
                               

''')
parser = argparse.ArgumentParser()
parser.add_argument('-u', help='Target Url For Scan')
args = parser.parse_args()


s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
   
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
    
    details = {}
   
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
   
    method = form.attrs.get("method", "get").lower()
   
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def is_vulnerable(response):
   
    errors = {
       
        "you have an error in your sql syntax;",
        "warning: mysql",
       
        "unclosed quotation mark after the character string",
        
        "quoted string not properly terminated",
    }
    for error in errors:
       
        if error in response.content.decode().lower():
            return True
   
    return False

def scan_sql_injection(url):
   
    for c in "\"'":
       
        new_url = f"{url}{c}"
        
      
        res = s.get(new_url)
        if is_vulnerable(res):
           
            print(f"{Gr}[+] {Wh}SQL Injection vulnerability detected, link:", new_url)
            return
   
    forms = get_all_forms(url)
    
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
           
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    
                   
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                   
                    data[input_tag["name"]] = f"test{c}"
           
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
         
            if is_vulnerable(res):
                print(f"{Gr}[+] {Wh}SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                break


   
    










def get_all_forms(url):
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
   
    details = {}
    
    action = form.attrs.get("action", "").lower()
  
    method = form.attrs.get("method", "get").lower()
    
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
   
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    
    
    target_url = urljoin(url, form_details["action"])
   
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
           
            data[input_name] = input_value

    
    print(f"[+] Data: {data}")
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        
        return requests.get(target_url, params=data)

def scan_xss(url ):
  
   
    forms = get_all_forms(url)
  
    js_script = "<Script>alert('hi')</scripT>"
    js_script2 = "<img src=x onclick=alert('The Jordan Ghost')"
    
    is_vulnerable = False
    
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"{Gr}[+] {Wh} XSS Detected on {url}")
           
            
            print(f"[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
        else:
            print(f"{Gr}[+] {Wh}XSS Detected on {url}")
            
            
            
            print(f"{Gr}[*] Form details:")
            pprint(form_details)
            is_vulnerable = True
           
    return is_vulnerable


if __name__ == "__main__":
           
           
           print('')
           print(f'{Ye} [~] Scan Xss Bug:  ')
           scan_xss(args.u)
           print(f'{Ye} [~] Scan Sql injection Bug:')
           scan_sql_injection(args.u)
