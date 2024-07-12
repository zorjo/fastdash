from typing import Text
from fastapi_sso.sso.google import GoogleSSO
from fastapi import FastAPI, Depends, HTTPException,Request,Security,Form
from fastapi.security import APIKeyCookie
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import sqlite3
#from fastapi.security.utils import get_authorization_scheme_param
from fastapi.responses import RedirectResponse
import datetime
from fastapi.requests import Request
#from fastapi.security.oauth2 import OAuth2PasswordBearer
#from pydantic import BaseModel
#from google.oauth2 import id_token
#from google.auth.transport import requests
#import os
from fastapi_sso.sso.base import OpenID
from jose import jwt
import json

def read_json_file(file_path: str) -> dict:
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data
client=read_json_file("client.json")
SECRET_KEY="9ce9230d35ee14142be93578ca79a27030d0b2ad87b6aa3abbeabb535ea38df6"
GOOGLE_CLIENT_ID = client["web"]["client_id"]
GOOGLE_CLIENT_SECRET = client["web"]["client_secret"]

templates = Jinja2Templates(directory="templates")

conn = sqlite3.connect('checkbox_data.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS checkbox_values
             (email TEXT PRIMARY KEY,
              isdashboard BOOLEAN,
              ischatbox BOOLEAN)''')
conn.commit()
conn.close()



app = FastAPI()



# Google OAuth2 configuration
google_sso = GoogleSSO(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, "http://127.0.0.1:5000/auth/callback")


#def get_google_sso():
#    return GoogleSSO(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, "http://localhost:5000/login/google/redirect/")


async def get_logged_user(cookie:str=Security(APIKeyCookie(name="token")))-> OpenID:
    try:
        claims=jwt.decode(cookie,SECRET_KEY,algorithms=["HS256"])
        return OpenID(**claims["pld"])
    except Exception as error:
        print(error)
        raise HTTPException(status_code=401,detail="Invalid authentication credentials") from error
# Google OAuth2 flow

@app.get("/protected")
async def protected_endpoint(user: OpenID = Depends(get_logged_user)):
    """This endpoint will return a template html with the user's email.

    If the user is not logged, it will return a 401 error from `get_logged_user`."""
    return {
        "message": f"You are very welcome, {user.email}!",
    }

@app.get("/form", response_class=HTMLResponse)
async def read_form(request:Request,user: OpenID = Depends(get_logged_user)):
    return templates.TemplateResponse("form.html", {"request": request,"user":user.email})
#@app.get("/", response_class=HTMLResponse)
#async def read_form(request: Request):
#    return templates.TemplateResponse("form.html", {"request": request})

@app.post("/submit")
async def submit_form(user=Depends(get_logged_user),  isdashboard: bool = Form(False), ischatbox: bool = Form(False)):
    conn = sqlite3.connect('checkbox_data.db')
    c = conn.cursor()
    email=user.email
    c.execute("INSERT OR REPLACE INTO checkbox_values (email,isdashboard, ischatbox) VALUES (?,?, ?)",
              (email,isdashboard, ischatbox))
    conn.commit()
    conn.close()
    return {"message": "Data submitted successfully"}
@app.get("/results", response_class=HTMLResponse)
async def read_results(request: Request,user: OpenID = Depends(get_logged_user)):
    email=user.email
    conn = sqlite3.connect('checkbox_data.db')
    c = conn.cursor()
    c.execute("SELECT email,isdashboard, ischatbox FROM checkbox_values where email=? LIMIT 1",(email,))
    result = c.fetchone()
    conn.close()

    if result:
        print(result)
        email,isdashboard, ischatbox = result
        return templates.TemplateResponse("results.html", {
            "request": request,
            "email": user.email,
            "isdashboard": isdashboard,
            "ischatbox": ischatbox
        })
    else:
        return templates.TemplateResponse("results.html", {
            "request": request,
            "message": "No data available"
        })


@app.get("/auth/login")
async def login():
    """Redirect the user to the Google login page."""
    with google_sso:
        return await google_sso.get_login_redirect()


@app.get("/auth/logout")
async def logout():
    """Forget the user's session."""
    response = RedirectResponse(url="/protected")
    response.delete_cookie(key="token")
    return response


@app.get("/auth/callback")
async def login_callback(request: Request):
    """Process login and redirect the user to the protected endpoint."""
    with google_sso:
        openid = await google_sso.verify_and_process(request)
        if not openid:
            raise HTTPException(status_code=401, detail="Authentication failed")
    # Create a JWT with the user's OpenID
    expiration = datetime.datetime.now(tz=datetime.timezone.utc) + datetime.timedelta(days=1)
    token = jwt.encode({"pld": openid.dict(), "exp": expiration, "sub": openid.id,"alg":"HS256"}, key=SECRET_KEY, algorithm="HS256")
    response = RedirectResponse(url="/protected")
    response.set_cookie(
        key="token", value=token, expires=expiration
    )  # This cookie will make sure /protected knows the user
    return response

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("__main__:app", host="127.0.0.1", port=5000,reload=True)
# @app.get("/homepage")
# async def homepage(sso1=Depends(get_google_sso)):
#         return {"message": sso1.access_token}
# @app.get("/login/google")
# async def google_login():
#     with google_sso:
#         return await google_sso.get_login_redirect()
# #    return RedirectResponse(url=f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri=http://localhost:5000/login/google/redirect/&scope=openid%20email%20profile&access_type=offline&prompt=consent")
#
#
#
# @app.get("/login/google/redirect")
# async def google_redirect(request: Request):
#     with google_sso:
#         user = await google_sso.verify_and_process(request)
#         #google_sso.state
#     return google_sso.access_token
#     #token_url, state = await get_token(code)
#     #return RedirectResponse(f"http://localhost:5000/homepage?token={token_url}")
"""
<!-- templates/form.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checkbox Form</title>
</head>
<body>
    <h1>Checkbox Form</h1>
    <form action="/submit" method="post">
        <label>
            <input type="checkbox" name="isdashboard" value="true"> Checkbox 1
        </label><br>
        <label>
            <input type="checkbox" name="ischatbox" value="true"> Checkbox 2
        </label><br>
        <input type="submit" value="Submit">
    </form>
</body>
</html>

<!-- templates/results.html -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Checkbox Results</title>
</head>
<body>
    <h1>Checkbox Results</h1>
    {% if message %}
        <p>{{ message }}</p>
    {% else %}
        <p>Checkbox 1: {{ "Checked" if isdashboard else "Unchecked" }}</p>
        <p>Checkbox 2: {{ "Checked" if ischatbox else "Unchecked" }}</p>
        <p>Timestamp: {{ timestamp }}</p>
    {% endif %}
    <a href="/">Back to Form</a>
</body>
</html>
"""
"""
@app.get("/", response_class=HTMLResponse)
async def read_form(request: Request):
    return templates.TemplateResponse("form.html", {"request": request})

@app.post("/submit")
async def submit_form(isdashboard: bool = Form(False), ischatbox: bool = Form(False)):
    conn = sqlite3.connect('checkbox_data.db')
    c = conn.cursor()
    c.execute("INSERT INTO checkbox_values (isdashboard, ischatbox) VALUES (?, ?)",
              (isdashboard, ischatbox))
    conn.commit()
    conn.close()
    return {"message": "Data submitted successfully"}

@app.get("/results", response_class=HTMLResponse)
async def read_results(request: Request):
    conn = sqlite3.connect('checkbox_data.db')
    c = conn.cursor()
    c.execute("SELECT isdashboard, ischatbox, timestamp FROM checkbox_values ORDER BY id DESC LIMIT 1")
    result = c.fetchone()
    conn.close()

    if result:
        isdashboard, ischatbox, timestamp = result
        return templates.TemplateResponse("results.html", {
            "request": request,
            "isdashboard": isdashboard,
            "ischatbox": ischatbox,
            "timestamp": timestamp
        })
    else:
        return templates.TemplateResponse("results.html", {
            "request": request,
            "message": "No data available"
        })

# You'll need to create two HTML templates in a 'templates' directory:
# 1. form.html
# 2. results.html


"""
