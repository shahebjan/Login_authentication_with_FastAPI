from fastapi import FastAPI, Request, HTTPException
import jwt
import time
from datetime import datetime, timedelta
import pymysql

app = FastAPI()

secret_key = "s7890"

HEADER = {
    "alg": "HS256",
    "typ": "jwt"
}

Generated_token_expire_time = 10
used_tokens = set()

# This function will generate Token and will encode that.
def generate_token(username: str, password: str):
    expiration_time = datetime.utcnow() + timedelta(minutes=Generated_token_expire_time)
    payload = {
        "username": username,
        "password": password,
        "exp": expiration_time
    }
    encoded_token = jwt.encode(payload, key=secret_key, algorithm="HS256", headers=HEADER)
    return encoded_token

# When we hit this endpoint in postman, My generated token will get encrypted and show.
@app.get("/generate_token/")
def login(username: str, password: str):
    encoded_token = generate_token(username, password)
    return {"Generated token": encoded_token}

# When we hit this endpoint in postman, My token will get used and session will get expired. 
@app.post("/logout/")
def logout(request: Request):
    authorization_header = request.headers.get("Authorization")
    if authorization_header is None or not authorization_header.startswith("Bearer "):
        return "Invalid or missing token"
    else:
        encoded_token = authorization_header.replace("Bearer ", "")
        used_tokens.add(encoded_token)
        return "Logout successfull."


# This endpoint is to validate my token expiration.
@app.post("/login_check/")
def login_check(request: Request):
    authorization_header = request.headers.get("Authorization")
    if authorization_header is None or not authorization_header.startswith("Bearer "):
        return "Invalid or missing token"
    else:
        encoded_token = authorization_header.replace("Bearer ", "")
    try:
        if encoded_token in used_tokens:
            return "Session expired."
#This below code will take encrypted token and will decode and extract the data and will tell the validation.    
        decoded_token = jwt.decode(encoded_token, secret_key, algorithms=['HS256'])
        expiration_time = datetime.fromtimestamp(decoded_token["exp"])
        current_time = datetime.utcnow()
        if current_time>=expiration_time:
            return "Token expired"
        else:
            return {"message": "Your token is valid", "user_data": decoded_token}
    except Exception as e:
        return e
    
# This endpoint will insert data into database but before it will ask for token.
@app.post("/insert_user/")
def insert_user(request: Request):
    authorization_header = request.headers.get("Authorization")
    if authorization_header is None or not authorization_header.startswith("Bearer "):
        return "Invalid or missing token"
    else:
        encoded_token = authorization_header.replace("Bearer ", "")

    if encoded_token in used_tokens:
        return "Session expired"
    decoded_token = jwt.decode(encoded_token, secret_key, algorithms=['HS256'])
    username = decoded_token["username"]
    password = decoded_token["password"]
    try:
        conn = pymysql.connect(host='localhost', user='root', password='', database='ahaan_mirza')
        with conn.cursor() as cur:
            sql = "INSERT INTO fastapi (username, password) VALUES (%s, %s)"
            cur.execute(sql, (username, password))
            conn.commit()
            return "Data inserted successfully."
    except Exception as e:
        return e


