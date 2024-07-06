from fastapi_sso.sso.google import GoogleSSO
from fastapi import FastAPI, Depends, HTTPException,Request
from fastapi.security import APIKeyCookie
#from fastapi.security.utils import get_authorization_scheme_param
from fastapi.responses import RedirectResponse
import datetime
from fastapi.requests import Request
from fastapi import Security
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
    """This endpoint will say hello to the logged user.
    If the user is not logged, it will return a 401 error from `get_logged_user`."""
    return {
        "message": f"You are very welcome, {user.email}!",
    }


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

    uvicorn.run(app, host="127.0.0.1", port=5000)
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
