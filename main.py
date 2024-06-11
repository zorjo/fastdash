from fastapi import FastAPI
from pydantic import BaseModel



app = FastAPI()

class Item(BaseModel):
    name: str
    description: str = None
    date: str
    id: int


from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2
from fastapi.security.utils import get_authorization_scheme_param
from fastapi.responses import RedirectResponse
from fastapi.requests import Request
from fastapi.security.oauth2 import OAuth2PasswordBearer
from pydantic import BaseModel
from google.oauth2 import id_token
from google.auth.transport import requests
import os
import json
import aiohttp

class User(BaseModel):
    username: str
    email: str
    dashboard: bool
    chatbox: bool

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/login")
async def login():
    return {"message": "Login page"}

@app.get("/homepage")
async def homepage(token: str = Depends(oauth2_scheme)):
    return {"message": "Homepage"}
import json

def read_json_file(file_path: str) -> dict:
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data
client=read_json_file("client.json")

# Google OAuth2 configuration
from dotenv import load_dotenv
load_dotenv()
GOOGLE_CLIENT_ID = client["web"]["client_id"]
GOOGLE_CLIENT_SECRET = client["web"]["client_secret"]

# Google OAuth2 flow
@app.get("/login/google")
async def google_login():
    return RedirectResponse(url=f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri=http://localhost:5000/login/google/redirect/&scope=openid%20email%20profile&access_type=offline&prompt=consent")



@app.get("/login/google/redirect")
async def google_redirect(code: str):
    token_url, state = await get_token(code)
    return RedirectResponse(f"http://localhost:5000/homepage?token={token_url}")

async def get_token(code: str):
    token_url, error = await get_token_url(code)
    if error:
        return None, error
    id_token = await get_id_token(token_url)
    return token_url, None

async def get_token_url(code: str):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    data = {"grant_type": "authorization_code", "code": code, "redirect_uri": "http://localhost:5000/login/google/redirect", "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET}
    async with aiohttp.ClientSession() as session:
        async with session.post("https://oauth2.googleapis.com/token", headers=headers, data=data) as response:
            response_json = await response.json()
            if "error" in response_json:
                return None, response_json["error"]
            return response_json["access_token"], None

async def get_id_token(token_url: str):
    headers = {"Authorization": f"Bearer {token_url}"}
    async with aiohttp.ClientSession() as session:
        async with session.get("https://openidconnect.googleapis.com/v1/userinfo", headers=headers) as response:
            response_json = await response.json()
            return response_json["email"]

import uvicorn
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)
