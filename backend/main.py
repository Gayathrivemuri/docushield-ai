
from fastapi import FastAPI, Depends, Form, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import create_engine, String, Boolean, ForeignKey
from sqlalchemy.orm import DeclarativeBase, sessionmaker, Mapped, mapped_column
from pydantic import BaseModel
from pwdlib import PasswordHash
import os
import uuid
from fastapi import UploadFile, File
from datetime import datetime, timedelta, timezone
from jose import jwt
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware


load_dotenv()


JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

if not JWT_SECRET_KEY:
    raise RuntimeError("JWT_SECRET_KEY missing in backend/.env")

JWT_ALGORITHM = "HS256"

def create_access_token(user_id: int, role: str):
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "role": role,
        "exp": expire
    }

    return jwt.encode(
        payload,
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )

ACCESS_TOKEN_EXPIRE_MINUTES = 30


app = FastAPI(title="DocuShield AI API")


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


password_hash = PasswordHash.recommended()


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer"

DATABASE_URL = "sqlite:///./docushield.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(bind=engine)


class Base(DeclarativeBase):
    pass


class PermissionRequest(BaseModel):
    document_id: int
    username: str
    can_read: bool = True
    can_download: bool = True

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    email: Mapped[str] = mapped_column(String(200), unique=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    filename: Mapped[str] = mapped_column(String(255))
    original_name: Mapped[str] = mapped_column(String(255))
    owner_id: Mapped[int] = mapped_column()
    file_path: Mapped[str] = mapped_column(String(500))
    category: Mapped[str] = mapped_column(String(100), default="General")

    
class DocumentPermission(Base):
    __tablename__ = "document_permissions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id")
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id")
    )
    can_read: Mapped[bool] = mapped_column(Boolean, default=True)
    can_download: Mapped[bool] = mapped_column(Boolean, default=True)
    granted_by: Mapped[int] = mapped_column(
        ForeignKey("users.id")
    )
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )

    
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id")
    )

    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id")
    )

    action: Mapped[str] = mapped_column()

    timestamp: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc)
    )


    




Base.metadata.create_all(bind=engine)



from fastapi import HTTPException
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM]
        )

        user_id = payload.get("sub")

        if user_id is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid authentication token"
            )

    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    db = SessionLocal()

    try:
        user = db.query(User).filter(
            User.id == int(user_id)
        ).first()

        if not user or not user.is_active:
            raise HTTPException(
                status_code=401,
                detail="User not found or inactive"
            )

        return user

    finally:
        db.close()


@app.post("/documents/grant-permission")
def grant_permission(
    request: PermissionRequest,
    current_user: User = Depends(get_current_user)
):
    db = SessionLocal()

    try:
        document = db.query(Document).filter(
            Document.id == request.document_id,
            Document.owner_id == current_user.id
        ).first()

        if not document:
            raise HTTPException(
                status_code=404,
                detail="Document not found or not owned by you"
            )

        target_user = db.query(User).filter(
            User.username == request.username
        ).first()

        if not target_user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        if target_user.id == current_user.id:
            raise HTTPException(
                status_code=400,
                detail="You already own this document"
            )

        existing_permission = db.query(DocumentPermission).filter(
            DocumentPermission.document_id == document.id,
            DocumentPermission.user_id == target_user.id
        ).first()

        if existing_permission:
            existing_permission.can_read = request.can_read
            existing_permission.can_download = request.can_download
            existing_permission.granted_by = current_user.id

        else:
            permission = DocumentPermission(
                document_id=document.id,
                user_id=target_user.id,
                can_read=request.can_read,
                can_download=request.can_download,
                granted_by=current_user.id
            )

            db.add(permission)

        db.commit()

                # Save permission grant in audit log
        audit = AuditLog(
            user_id=current_user.id,
            document_id=document.id,
            action="grant_permission"
        )

        db.add(audit)
        db.commit()

        return {
            "message": "Permission granted successfully",
            "document_id": document.id,
            "username": target_user.username,
            "can_read": request.can_read,
            "can_download": request.can_download
        }

    finally:
        db.close()




        
@app.post("/documents/revoke-permission")
def revoke_permission(
    data: PermissionRequest,
    current_user: User = Depends(get_current_user)
):
    db = SessionLocal()

    try:
        # Check document ownership
        document = db.query(Document).filter(
            Document.id == data.document_id,
            Document.owner_id == current_user.id
        ).first()

        if not document:
            raise HTTPException(
                status_code=404,
                detail="Document not found or not owned by you"
            )

        # Find the user whose permission should be revoked
        target_user = db.query(User).filter(
            User.username == data.username
        ).first()

        if not target_user:
            raise HTTPException(
                status_code=404,
                detail="User not found"
            )

        permission = db.query(DocumentPermission).filter(
            DocumentPermission.document_id == data.document_id,
            DocumentPermission.user_id == target_user.id
        ).first()

        if not permission:
            raise HTTPException(
                status_code=404,
                detail="Permission not found"
            )

        db.delete(permission)
        db.commit()

                # Save permission revoke in audit log
        audit = AuditLog(
            user_id=current_user.id,
            document_id=document.id,
            action="revoke_permission"
        )

        db.add(audit)
        db.commit()

        return {
            "message": "Permission revoked successfully",
            "document_id": data.document_id,
            "username": target_user.username
        }

    finally:
        db.close()



@app.get("/")
def home():
    return {"message": "DocuShield AI backend is running!"}


@app.get("/health")
def health_check():
    return {"status": "healthy"}

    
@app.get("/audit-logs")
def get_audit_logs(
    current_user: User = Depends(get_current_user)
):
    db = SessionLocal()

    try:
        if current_user.role != "owner":
            raise HTTPException(
                status_code=403,
                detail="Only owners can view audit logs"
            )

        logs = db.query(AuditLog).order_by(
            AuditLog.timestamp.desc()
        ).all()

        return [
            {
                "id": log.id,
                "user_id": log.user_id,
                "document_id": log.document_id,
                "action": log.action,
                "timestamp": log.timestamp
            }
            for log in logs
        ]

    finally:
        db.close()




    
from fastapi import HTTPException


@app.post("/register")
def register_user(data: RegisterRequest):
    db = SessionLocal()

    try:
        existing_user = db.query(User).filter(
            (User.username == data.username) |
            (User.email == data.email)
        ).first()

        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Username or email already exists"
            )

        if data.role not in ["owner", "viewer"]:
            raise HTTPException(
                status_code=400,
                detail="Role must be owner or viewer"
            )

        user = User(
            username=data.username,
            email=data.email,
            hashed_password=password_hash.hash(data.password),
            role=data.role
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return {
            "message": "Registration successful",
            "user_id": user.id,
            "username": user.username,
            "role": user.role
        }

    finally:
        db.close()



class LoginRequest(BaseModel):
    username: str
    password: str

class TokenRequest(BaseModel):
    username: str
    password: str

@app.post("/login")
def login_user(data: LoginRequest):
    db = SessionLocal()

    try:
        user = db.query(User).filter(
            User.username == data.username
        ).first()

        if not user or not password_hash.verify(
            data.password, user.hashed_password
        ):
            raise HTTPException(
                status_code=401,
                detail="Invalid username or password"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=403,
                detail="Account is disabled"
            )

        
        access_token = create_access_token(
            user_id=user.id,
            role=user.role
        )

        return {
            "message": "Login successful",
            "access_token": access_token,
            "token_type": "bearer",
            "user_id": user.id,
            "username": user.username,
            "role": user.role
        }


    finally:
        db.close()

@app.post("/token")
def login_for_swagger(username: str = Form(...), password: str = Form(...)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.username == username
        ).first()

        if not user or not password_hash.verify(
            password, user.hashed_password
        ):
            raise HTTPException(
                status_code=401,
                detail="Incorrect username or password"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=401,
                detail="User is inactive"
            )

        return {
            "access_token": create_access_token(user.id, user.role),
            "token_type": "bearer"
        }
    finally:
        db.close()


        
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

ALLOWED_EXTENSIONS = {".pdf", ".docx", ".txt", ".png", ".jpg", ".jpeg"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB


@app.post("/documents/upload")
async def upload_document(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    extension = os.path.splitext(file.filename or "")[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="File type not allowed"
        )

    contents = await file.read()

    if not contents:
        raise HTTPException(status_code=400, detail="Empty file")

    if len(contents) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File must be 5 MB or smaller"
        )

    safe_filename = f"{uuid.uuid4().hex}{extension}"
    file_path = os.path.join(UPLOAD_DIR, safe_filename)

    with open(file_path, "wb") as saved_file:
        saved_file.write(contents)

    
    db = SessionLocal()

    try:
        document = Document(
            filename=safe_filename,
            original_name=file.filename or "unnamed",
            owner_id=current_user.id,
            file_path=file_path,
            category="General"
        )

       
        db.add(document)
        db.commit()
        db.refresh(document)

        # Save upload action in audit log
        audit = AuditLog(
            user_id=current_user.id,
            document_id=document.id,
            action="upload"
        )

        db.add(audit)
        db.commit()

        return {
            "message": "File uploaded and saved successfully",
            "document_id": document.id,
            "filename": document.original_name,
            "owner_id": document.owner_id
        }


        return {
            "message": "File uploaded and saved successfully",
            "document_id": document.id,
            "filename": document.original_name,
            "owner_id": document.owner_id
        }

    finally:
        db.close()



@app.get("/documents")
def list_documents(current_user: User = Depends(get_current_user)):
    db = SessionLocal()

    try:
        # Get documents owned by current user
        owned_documents = db.query(Document).filter(
            Document.owner_id == current_user.id
        ).all()

        # Get documents shared with current user
        shared_permissions = db.query(DocumentPermission).filter(
            DocumentPermission.user_id == current_user.id,
            DocumentPermission.can_read == True
        ).all()

        shared_document_ids = [
            permission.document_id
            for permission in shared_permissions
        ]

        shared_documents = db.query(Document).filter(
            Document.id.in_(shared_document_ids)
        ).all()

        # Combine owned and shared documents
        all_documents = owned_documents + shared_documents

        return [
            {
                "id": doc.id,
                "filename": doc.original_name,
                "owner_id": doc.owner_id,
                "category": doc.category
            }
            for doc in all_documents
        ]

    finally:
        db.close()





@app.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    current_user: User = Depends(get_current_user)
):
    db = SessionLocal()

    try:
        document = db.query(Document).filter(
            Document.id == document_id
        ).first()

        if not document:
            raise HTTPException(
                status_code=404,
                detail="Document not found"
            )

        # Owner can download
        if document.owner_id == current_user.id:
            audit = AuditLog(
                user_id=current_user.id,
                document_id=document.id,
                action="download"
            )

            db.add(audit)
            db.commit()

            return FileResponse(
                path=document.file_path,
                filename=document.original_name
            )

        # Check download permission
        permission = db.query(DocumentPermission).filter(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == current_user.id
        ).first()

        if (
            not permission
            or not permission.can_read
            or not permission.can_download
        ):
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to download this document"
            )

        # Save shared user download in audit log
        audit = AuditLog(
            user_id=current_user.id,
            document_id=document.id,
            action="download"
        )

        db.add(audit)
        db.commit()

        return FileResponse(
            path=document.file_path,
            filename=document.original_name
        )

    finally:
        db.close()

