# #    link for runAccess your app via [ http://localhost:8000 ] (not 127.0.0.1)

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv
from supabase import create_client, Client
import os
import msal
import requests
from datetime import datetime

# Load environment variables
load_dotenv()

# Supabase client setup
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# FastAPI app setup
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SECRET_KEY", "randomsecret"))
templates = Jinja2Templates(directory="templates")

# OAuth setup
oauth = OAuth()

# Google
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Facebook
oauth.register(
    name='facebook',
    client_id=os.getenv("FACEBOOK_CLIENT_ID"),
    client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
    access_token_url='https://graph.facebook.com/v12.0/oauth/access_token',
    authorize_url='https://www.facebook.com/v12.0/dialog/oauth',
    api_base_url='https://graph.facebook.com/v12.0/',
    client_kwargs={'scope': 'email public_profile'}
)

# Microsoft (MSAL)
CLIENT_ID = os.getenv("AZURE_CLIENT_ID")
CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET")
TENANT_ID = os.getenv("AZURE_TENANT_ID", "common")
AUTHORITY = os.getenv("AZURE_AUTHORITY", f"https://login.microsoftonline.com/{TENANT_ID}")
REDIRECT_URI = os.getenv("AZURE_REDIRECT_URI")
SCOPE = ["User.Read"]

def _build_msal_app(cache=None):
    return msal.ConfidentialClientApplication(
        CLIENT_ID, authority=AUTHORITY,
        client_credential=CLIENT_SECRET, token_cache=cache
    )

def _build_auth_url():
    return _build_msal_app().get_authorization_request_url(
        SCOPE, redirect_uri=REDIRECT_URI
    )

# ================== Helper: Save to Supabase ==================
def save_user(provider: str, provider_id: str, name: str, email: str, picture: str, raw_data: dict):
    data = {
        "provider": provider,
        "provider_user_id": provider_id,
        "name": name,
        "email": email,
        "profile_picture": picture,
        "raw_data": raw_data,
        "updated_at": datetime.utcnow().isoformat()
    }

    # First try insert; if duplicate, update
    existing = supabase.table("auth_users").select("*").eq("provider", provider).eq("provider_user_id", provider_id).execute()
    if existing.data:
        supabase.table("auth_users").update(data).eq("provider", provider).eq("provider_user_id", provider_id).execute()
    else:
        supabase.table("auth_users").insert(data).execute()

# ================== Routes ==================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = request.session.get("user")
    return templates.TemplateResponse("home.html", {"request": request, "user": user})

# ---------- Google ----------
@app.get("/login/google")
async def login_google(request: Request):
    redirect_uri = request.url_for('auth_google')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@app.get("/auth/google")
async def auth_google(request: Request):
    try:
        token = await oauth.google.authorize_access_token(request)
        user_info = await oauth.google.userinfo(token=token)
        user_data = dict(user_info)

        save_user(
            provider="google",
            provider_id=user_data.get("sub"),
            name=user_data.get("name"),
            email=user_data.get("email"),
            picture=user_data.get("picture"),
            raw_data=user_data
        )

        request.session['user'] = user_data
        return RedirectResponse(url="/")
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "message": str(e)})

# ---------- Facebook ----------
@app.get("/login/facebook")
async def login_facebook(request: Request):
    redirect_uri = str(request.url_for('auth_facebook'))
    return await oauth.facebook.authorize_redirect(request, redirect_uri)

@app.get("/auth/facebook")
async def auth_facebook(request: Request):
    try:
        token = await oauth.facebook.authorize_access_token(request)
        resp = await oauth.facebook.get('me?fields=id,name,email,picture', token=token)
        user_info = resp.json()

        save_user(
            provider="facebook",
            provider_id=user_info.get("id"),
            name=user_info.get("name"),
            email=user_info.get("email"),
            picture=user_info.get("picture", {}).get("data", {}).get("url"),
            raw_data=user_info
        )

        request.session['user'] = user_info
        return RedirectResponse(url="/")
    except Exception as e:
        return templates.TemplateResponse("error.html", {"request": request, "message": str(e)})

# ---------- Microsoft ----------
@app.get("/login/microsoft")
async def login_microsoft():
    return RedirectResponse(_build_auth_url())

@app.get("/auth/redirect")
async def auth_redirect(request: Request):
    code = request.query_params.get("code")
    if not code:
        return {"error": "Missing authorization code"}

    result = _build_msal_app().acquire_token_by_authorization_code(
        code,
        scopes=SCOPE,
        redirect_uri=REDIRECT_URI
    )

    if "error" in result:
        return {"error": result.get("error"), "description": result.get("error_description")}

    access_token = result["access_token"]
    graph_data = requests.get(
        "https://graph.microsoft.com/v1.0/me",
        headers={"Authorization": f"Bearer {access_token}"}
    ).json()

    save_user(
        provider="microsoft",
        provider_id=graph_data.get("id"),
        name=graph_data.get("displayName"),
        email=graph_data.get("mail") or graph_data.get("userPrincipalName"),
        picture=None,
        raw_data=graph_data
    )

    request.session["user"] = graph_data
    return RedirectResponse("/")

# ---------- Logout ----------
@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/")
