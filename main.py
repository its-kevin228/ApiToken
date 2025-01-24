from datetime import datetime, timedelta
import bcrypt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import os
import mysql.connector
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Configuration de l'application FastAPI
app = FastAPI()

# Connexion à la base de données
DB_CONFIG = {
    "user": "root",
    "password": "",
    "host": "localhost",
    "database": "fastapi",
}

# Configuration pour JWT
SECRET_KEY = os.getenv("SECRET_KEY", "default_secret")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

# Configuration pour le hachage des mots de passe
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# Fonction pour obtenir un curseur
def get_db_cursor():
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn, conn.cursor(dictionary=True)
    except mysql.connector.Error as e:
        raise HTTPException(status_code=500, detail=f"Erreur de connexion à la base de données : {e}")


# Fonction pour insérer un utilisateur dans la base de données
def insert_user(username: str, password: str):
    conn, cursor = get_db_cursor()  # Connexion à la base de données
    try:
        hashed_password = pwd_context.hash(password)  # Hachage du mot de passe
        query = "INSERT INTO users (username, hashed_password) VALUES (%s, %s)"
        cursor.execute(query, (username, hashed_password))  # Exécution de la requête
        conn.commit()  # Commit des changements
        print(f"Utilisateur {username} ajouté avec succès.")
    except Exception as e:
        print(f"Erreur lors de l'ajout de l'utilisateur : {e}")
    finally:
        cursor.close()
        conn.close()


# Ajout d'un utilisateur de test
insert_user("testuser", "password123!")

# Fonction pour récupérer un utilisateur dans la base de données
def get_user_from_db(username: str):
    conn, cursor = get_db_cursor()
    try:
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


# Fonction pour créer un token JWT
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# Modèles Pydantic
class Token(BaseModel):
    access_token: str
    token_type: str


class User(BaseModel):
    username: str
    password: str


# Endpoint : Générer un token
@app.post("/token", response_model=Token)
async def login_for_access_token(user: User):
    db_user = get_user_from_db(user.username)
    if db_user is None or not pwd_context.verify(user.password, db_user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nom d'utilisateur ou mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}


# Endpoint : Valider le token
@app.get("/validate_token")
async def validate_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Token invalide")
        return {"username": username, "valid": True}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide")


# Endpoint : Route protégée
@app.get("/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Token invalide")
        return {"username": username, "message": "Authentification réussie"}
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Token invalide : {e}")


# Endpoint : Racine
@app.get("/")
def root():
    return {"message": "Bienvenue sur l'API Token"}
