from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt
from pydantic import BaseModel

# Configuración de la Base de Datos (con corrección para SQLite)
DATABASE_URL = "sqlite:///./codemastery.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})  # <- Cambio aquí
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Modelo de Usuario (con longitudes definidas)
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)  # Longitud máxima 50
    hashed_password = Column(String(255))  # Longitud para el hash

# Modelo de Curso
class Course(Base):
    __tablename__ = "courses"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(100), index=True)  # Longitud máxima 100
    description = Column(String(500))  # Longitud máxima 500

Base.metadata.create_all(bind=engine)

# Seguridad
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Esquemas Pydantic
class UserCreate(BaseModel):
    username: str
    password: str

class CourseCreate(BaseModel):
    title: str
    description: str

# API
app = FastAPI()

# Endpoint /register con manejo de errores
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    
    try:
        hashed_password = get_password_hash(user.password)
        db_user = User(username=user.username, hashed_password=hashed_password)
        db.add(db_user)
        db.commit()
        return {"message": "Usuario registrado"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

# Resto de endpoints sin cambios...

@app.post("/login")
def login(user: UserCreate, db: Session = Depends(get_db)):  # Cambio importante
    db_user = db.query(User).filter(User.username == user.username).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas")
    access_token = create_access_token({"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/courses")
def create_course(course: CourseCreate, db: Session = Depends(get_db)):  # Cambio importante
    db_course = Course(title=course.title, description=course.description)
    db.add(db_course)
    db.commit()
    return {"message": "Curso creado"}

@app.get("/courses")
def get_courses(db: Session = Depends(get_db)):  # Cambio importante
    return db.query(Course).all()

