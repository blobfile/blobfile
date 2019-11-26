from typing import Union
from Cryptodome import PublicKey, Hash

from Cryptodome.Signature import pkcs1_15

def new(rsa_key: PublicKey.RSA) -> pkcs1_15.PKCS115_SigScheme: ...

class PKCS115_SigScheme:
    def sign(self, msg_hash: Union[Hash.SHA256]) -> bytes: ...
