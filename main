
from fastapi import FastAPI, HTTPException, Header, Path
from pydantic import BaseModel
from typing import Optional
import base64

app = FastAPI()

# In-memoryユーザーデータベース（本番環境ではDBに置換）
fake_users_db = {
    "TaroYamada": {
        "password": "paSSwd4TY",
        "nickname": "たろー",
        "comment": "僕は元気です"
    }
}

# -----------------------------------------
# データモデル定義
# -----------------------------------------
class SignUpRequest(BaseModel):
    user_id: str
    password: str

class UserUpdateRequest(BaseModel):
    nickname: Optional[str] = None
    comment: Optional[str] = None

# -----------------------------------------
# ヘルパー関数
# -----------------------------------------
def decode_auth_header(authorization: str):
    if not authorization or not authorization.startswith("Basic "):
        raise HTTPException(status_code=401, detail="Authorizationヘッダが必要です")
    try:
        encoded = authorization.split(" ")[1]
        decoded = base64.b64decode(encoded).decode("utf-8")
        user_id, password = decoded.split(":", 1)
        return user_id, password
    except Exception:
        raise HTTPException(status_code=401, detail="Authorizationヘッダが不正です")

def is_valid_user_id(uid: str):
    return 6 <= len(uid) <= 20 and uid.isalnum()

def is_valid_password(pw: str):
    return 8 <= len(pw) <= 20 and all(33 <= ord(c) <= 126 for c in pw)

# -----------------------------------------
# POST /signup
# -----------------------------------------
@app.post("/signup")
def signup(req: SignUpRequest):
    uid = req.user_id
    pw = req.password

    if not is_valid_user_id(uid):
        raise HTTPException(status_code=400, detail={"cause": "user_idは6〜20文字の半角英数字でなければなりません"})
    if not is_valid_password(pw):
        raise HTTPException(status_code=400, detail={"cause": "passwordは8〜20文字のASCII文字を使用してください"})
    if uid in fake_users_db:
        raise HTTPException(status_code=400, detail={"cause": "指定されたuser_idは既に登録されています"})

    fake_users_db[uid] = {"password": pw}
    return {"message": "アカウントが正常に作成されました"}

# -----------------------------------------
# GET /users/{user_id}
# -----------------------------------------
@app.get("/users/{user_id}")
def get_user(user_id: str, authorization: Optional[str] = Header(None)):
    if user_id not in fake_users_db:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません")

    auth_uid, auth_pw = decode_auth_header(authorization)
    if auth_uid != user_id:
        raise HTTPException(status_code=401, detail="認証に失敗しました")
    user = fake_users_db[user_id]
    if user["password"] != auth_pw:
        raise HTTPException(status_code=401, detail="認証に失敗しました")

    return {
        "user_id": user_id,
        "nickname": user.get("nickname", user_id),
        "comment": user.get("comment", "")
    }

# -----------------------------------------
# PATCH /users/{user_id}
# -----------------------------------------
@app.patch("/users/{user_id}")
def update_user(
    user_id: str = Path(...),
    req: UserUpdateRequest = None,
    authorization: Optional[str] = Header(None)
):
    auth_uid, auth_pw = decode_auth_header(authorization)

    if user_id not in fake_users_db:
        raise HTTPException(status_code=404, detail="ユーザーが存在しません")
    if auth_uid != user_id:
        raise HTTPException(status_code=403, detail="他ユーザーの情報は更新できません")
    if fake_users_db[user_id]["password"] != auth_pw:
        raise HTTPException(status_code=401, detail="認証失敗")

    if req.nickname is None and req.comment is None:
        raise HTTPException(status_code=400, detail="nicknameまたはcommentのいずれかは必須です")

    if req.nickname is not None:
        if len(req.nickname) > 30:
            raise HTTPException(status_code=400, detail="nicknameは30文字以内")
        fake_users_db[user_id]["nickname"] = req.nickname if req.nickname else user_id

    if req.comment is not None:
        if len(req.comment) > 100:
            raise HTTPException(status_code=400, detail="commentは100文字以内")
        fake_users_db[user_id]["comment"] = req.comment

    return {
        "user_id": user_id,
        "nickname": fake_users_db[user_id].get("nickname", user_id),
        "comment": fake_users_db[user_id].get("comment", "")
    }

# -----------------------------------------
# POST /close
# -----------------------------------------
@app.post("/close")
def close_account(authorization: Optional[str] = Header(None)):
    auth_uid, auth_pw = decode_auth_header(authorization)

    user = fake_users_db.get(auth_uid)
    if not user or user["password"] != auth_pw:
        raise HTTPException(status_code=401, detail="認証に失敗しました")

    del fake_users_db[auth_uid]
    return {"message": f"アカウント {auth_uid} を削除しました"}
