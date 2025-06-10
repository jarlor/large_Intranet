from pydantic import BaseModel, Field
from typing import List, Optional

class Proxy(BaseModel):
    name: str
    type: str
    localIP: str
    localPort: int
    remotePort: int

class FrpcConfig(BaseModel):
    serverAddr: str
    serverPort: int
    proxies: List[Proxy]

