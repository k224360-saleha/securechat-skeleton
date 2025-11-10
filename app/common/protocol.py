"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt.""" 
from pydantic import BaseModel, Field, ConfigDict
from typing import Literal

class Model(BaseModel):
    model_config = ConfigDict(populate_by_name=True) 

# === CLIENT → SERVER MESSAGES ===

class ClientHello(Model):
    type: Literal["hello"]
    client_cert: str = Field(alias="client cert", description="PEM-encoded client certificate")
    nonce: str  # base64-encoded nonce


class ClientRegister(Model):
    type: Literal["register"]
    email: str
    username: str
    pwd: str  # raw password (client side before hashing)


class ClientLogin(Model):
    type: Literal["login"]
    email: str
    pwd: str = Field(description="base64(sha256(salt||pwd))")
    nonce: str  # base64 encoded

class ClientDH(Model):
    type: Literal["dh client"]
    g: int
    p: int
    A: int # client public value (g^a mod p)

# === SERVER → CLIENT MESSAGES ===

class ServerHello(Model):
    type: Literal["server hello"]
    server_cert: str = Field(alias="server cert", description="PEM-encoded server certificate")
    nonce: str  # base64-encoded nonce

class ServerRegisterResponse(Model):
    type: Literal["Register"]
    status: Literal["ok", "error"]

class ServerLoginResponse(Model):
    type: Literal["login"]
    status: Literal["ok", "error"]
    
class ServerDH(Model):
    type: Literal["dh server"]
    B: int  # server public value (g^b mod p)

class ServerError(Model):
    type: Literal["error"]
    message: str

