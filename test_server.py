from fastapi import FastAPI, Query, Body, Header
from fastapi.responses import JSONResponse
import subprocess
import sqlite3
from pydantic import BaseModel
from typing import Optional

app = FastAPI()

# テスト用データベースの初期化
def initialize_db():
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'password123')")
    conn.commit()
    conn.close()

initialize_db()


# XSSエンドポイント
@app.get("/xss")
async def xss_test(payload: Optional[str] = Query(None)):
    response = f"<div>{payload}</div>" if payload else "<div>No Payload</div>"
    return JSONResponse(content={"html": response}, media_type="application/json")


# SQLインジェクションエンドポイント
@app.get("/sql")
async def sql_injection(payload: str = Query(...)):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    try:
        query = f"SELECT * FROM users WHERE username='{payload}'"
        cursor.execute(query)
        rows = cursor.fetchall()
        return {"query": query, "result": rows}
    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()


# OSコマンドインジェクションエンドポイント
@app.get("/os")
async def os_command_injection(command: str = Query(...)):
    try:
        output = subprocess.check_output(command, shell=True, text=True)
        return {"command": command, "output": output}
    except Exception as e:
        return {"error": str(e)}


# JSONインジェクションエンドポイント
class JsonPayload(BaseModel):
    username: str
    password: Optional[str] = None

@app.post("/json")
async def json_injection(payload: JsonPayload = Body(...)):
    if "admin" in payload.username:
        return {"message": "Admin access granted"}
    else:
        return {"message": "Access denied"}


# HTTPヘッダーインジェクションエンドポイント
@app.get("/header")
async def header_injection(user_agent: Optional[str] = Header(None)):
    return {"User-Agent": user_agent}


# LDAPインジェクション（シミュレーション）
@app.get("/ldap")
async def ldap_injection(payload: str = Query(...)):
    fake_ldap_query = f"(uid={payload})"
    if "*&" in payload:
        return {"message": "Potential LDAP injection detected", "query": fake_ldap_query}
    else:
        return {"message": "LDAP query executed", "query": fake_ldap_query}


# CRLFインジェクションエンドポイント
@app.get("/crlf")
async def crlf_injection(payload: str = Query(...)):
    if "\r\n" in payload:
        return {"message": "Potential CRLF injection detected", "payload": payload}
    else:
        return {"message": "Payload processed safely", "payload": payload}


# サーバー起動用
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
