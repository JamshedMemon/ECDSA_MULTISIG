from ecdsa import SigningKey, VerifyingKey, SECP256k1
import hashlib
from typing import List, Tuple, Dict

class ECDSAMultiSig:
    def __init__(self, required_signatures: int, total_participants: int):
        """
        Initialize ECDSA multisig system
        required_signatures: minimum number of signatures needed
        total_participants: total number of participants
        """
        if required_signatures > total_participants:
            raise ValueError("Required signatures cannot exceed total participants")
        
        self.required_signatures = required_signatures
        self.total_participants = total_participants
        self.participants: List[Dict] = []
        
    def generate_keypair(self) -> Dict[str, str]:
        """Generate a new ECDSA keypair"""
        private_key = SigningKey.generate(curve=SECP256k1)
        public_key = private_key.get_verifying_key()
        
        return {
            'private_key': private_key.to_string().hex(),
            'public_key': public_key.to_string().hex()
        }
    
    def add_participant(self, public_key: str) -> None:
        """Add a participant using their public key"""
        if len(self.participants) >= self.total_participants:
            raise ValueError("Maximum participants reached")
        
        participant = {
            'public_key': public_key,
            'index': len(self.participants)
        }
        self.participants.append(participant)
        print(f"Added participant {participant['index']} with public key: {public_key[:10]}...")
    
    def create_message_hash(self, message: str) -> bytes:
        """Create a hash of the message to be signed"""
        return hashlib.sha256(message.encode()).digest()
    
    def sign_message(self, message_hash: bytes, private_key: str) -> str:
        """Sign a message hash with a private key"""
        signing_key = SigningKey.from_string(bytes.fromhex(private_key), curve=SECP256k1)
        signature = signing_key.sign(message_hash)
        return signature.hex()
    
    def verify_signature(self, message_hash: bytes, signature: str, public_key: str) -> bool:
        """Verify a single signature"""
        try:
            verifying_key = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
            verifying_key.verify(bytes.fromhex(signature), message_hash)
            return True
        except:
            return False
    
    def verify_message(self, message_hash: bytes, signatures: List[Tuple[str, str]]) -> bool:
        """
        Verify if a message has enough valid signatures
        signatures: List of (signature, public_key) tuples
        """
        valid_signatures = 0
        used_participants = set()
        
        for signature, public_key in signatures:
            # Check if public key belongs to a participant
            if public_key not in [p['public_key'] for p in self.participants]:
                print(f"Invalid public key: {public_key[:10]}...")
                continue
            
            # Prevent duplicate signatures from same participant
            if public_key in used_participants:
                print(f"Duplicate signature from: {public_key[:10]}...")
                continue
                
            if self.verify_signature(message_hash, signature, public_key):
                valid_signatures += 1
                used_participants.add(public_key)
                print(f"Valid signature from: {public_key[:10]}...")
            else:
                print(f"Invalid signature from: {public_key[:10]}...")
                
        return valid_signatures >= self.required_signatures

# Make sure the class is available for import
__all__ = ['ECDSAMultiSig']