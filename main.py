from fastapi_sso.sso.google import GoogleSSO
from fastapi import FastAPI, Depends,Security,Request
from fastapi.security import OAuth2PasswordBearer,APIKeyCookie
#from fastapi.security.utils import get_authorization_scheme_param
#from fastapi.responses import RedirectResponse
from fastapi.requests import Request
from fastapi.security.oauth2 import OAuth2PasswordBearer
from pydantic import BaseModel
#from google.oauth2 import id_token
#from google.auth.transport import requests
#import os

import json

def read_json_file(file_path: str) -> dict:
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data
client=read_json_file("client.json")
SECRET_KEY="9ce9230d35ee14142be93578ca79a27030d0b2ad87b6aa3abbeabb535ea38df6"
GOOGLE_CLIENT_ID = client["web"]["client_id"]
GOOGLE_CLIENT_SECRET = client["web"]["client_secret"]
app = FastAPI()

class Item(BaseModel):
    name: str
    description: str = ""
    date: str
    id: int
class User(BaseModel):
    username: str
    email: str
    dashboard: bool
    chatbox: bool

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/login")
async def login():
    return {"message": "Login page"}


# Google OAuth2 configuration
google_sso = GoogleSSO(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, "http://localhost:5000/login/google/redirect/")


def get_google_sso():
    return GoogleSSO(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, "http://localhost:5000/login/google/redirect/")


# Google OAuth2 flow
@app.get("/homepage")
async def homepage(sso1=Depends(get_google_sso)):
        return {"message": sso1.access_token}
@app.get("/login/google")
async def google_login():
    with google_sso:
        return await google_sso.get_login_redirect()
#    return RedirectResponse(url=f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri=http://localhost:5000/login/google/redirect/&scope=openid%20email%20profile&access_type=offline&prompt=consent")



@app.get("/login/google/redirect")
async def google_redirect(request: Request):
    with google_sso:
        user = await google_sso.verify_and_process(request)
        #google_sso.state
    return google_sso.access_token
    #token_url, state = await get_token(code)
    #return RedirectResponse(f"http://localhost:5000/homepage?token={token_url}")
