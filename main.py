from binascii import Error
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
import os  # Pour accéder aux variables d'environnement
import mysql.connector
from dotenv import load_dotenv # type: ignore

# Configuration de l'application FastAPI
app = FastAPI()
#charger les variables d'env depuis le fichier .env
load_dotenv()



#connexion a la base de donnees
config = {
    "username": "root",
    "password": "",
    "host": "localhost",
    "database": "fastapi",
}

#etablir la connexion 
try:
    cnx = mysql.connector.connect(**config)
    cursor= cnx.cursor(dictionary=True)
    print("Connexion a la base de donnees reussie")

except Error as e :
    print(f"Erreur lors de la connexion a la base de donnees : {e}")
    raise


def get_user_from_db(username:str):
    #requete sql avec placeholder '%s' pour eviter les injections sql
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    return user

# Configuration pour le hachage des mots de passe
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configuration pour JWT
SECRET_KEY = os.getenv("SECRET_KEY")  # Clé secrète par défaut
ALGORITHM = os.getenv("ALGORITHM", "HS256")  # Algorithme par défaut
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))  # Convertir en entier

# Modèle Pydantic pour le token
class Token(BaseModel):
    access_token: str
    token_type: str

# Modèle Pydantic pour les données utilisateur
class User(BaseModel):
    username: str
    password: str

# Fonction pour vérifier le mot de passe
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Fonction pour créer un token JWT
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Endpoint pour générer un token
@app.post("/token", response_model=Token)
async def login_for_access_token(user: User):
   
    # Récupérer l'utilisateur depuis la base de données
    db_user = get_user_from_db(user.username)
    
    # Vérifier si l'utilisateur existe
    if db_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Utilisateur non trouvé",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Vérifier le mot de passe
    if not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Mot de passe incorrect",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # Utilisation de la valeur convertie
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Endpoint pour valider le token
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/validate_token")
async def validate_token(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Désolé votre token n'est pas valide",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError as e:
        raise credentials_exception
    return {"username": username, "valid": True}

# Endpoint protégé
@app.get("/protected")
async def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        return {"username": username, "message": "c'est bon vous etes authentifier!"}
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
        )

# Endpoint racine
@app.get("/")
def root():
    return {"message": "Bienvenue sur l'API Token"}