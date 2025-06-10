from pydantic import BaseModel, Field
from typing import List, Optional

class Proxy(BaseModel):
    name: str
    type: str
    localIP: str
    localPort: int
    remotePort: int
    disabled: Optional[bool] = False

class FrpcConfig(BaseModel):
    serverAddr: str
    serverPort: int
    proxies: List[Proxy]

