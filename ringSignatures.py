import os, hashlib, random, Crypto.PublicKey.RSA
import sys
from functools import reduce
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.curves import Curve
from ecdsa.ellipticcurve import Point, PointJacobi

class Ring: 
    def __init__(self, public_keys: list[PointJacobi], curve: Curve):
        self.public_keys = public_keys #TODO: list of public keys
        self.curve = curve

    def glue(self, msg: str):
        """
        Generate a message-dependent permutation value using SHA-1. Signature is bound to a specific message.

        Args: 
            m: message
        """
        return int(hashlib.sha1(msg).hexdigest(),16)

    def hash_point(self, point) -> int:

        """
        Point hash function.
        Hashes a single public key point to a scalar.
        """
        hasher = hashlib.sha256()
        n = self.curve.order
        # Add domain separator to distinguish from H()
        hasher.update(b'H_p:')
        
        # Hash the point coordinates
        hasher.update(point.x().to_bytes(32, 'big'))
        hasher.update(point.y().to_bytes(32, 'big'))
        
        hash_int = int.from_bytes(hasher.digest(), 'big')
        return hash_int % n  # Return scalar

    def hash_challenge(self, *args) -> int:
        """
        Challenge hash function.
        Hashes message and all commitment points.
        """
        hasher = hashlib.sha256()
        n = self.curve.order
        for arg in args:
            # Hash all inputs together
            if isinstance(arg, bytes):
                hasher.update(arg)
            elif hasattr(arg, 'x'):  # Point
                hasher.update(arg.x().to_bytes(32, 'big'))
                hasher.update(arg.y().to_bytes(32, 'big'))
        
        hash_int = int.from_bytes(hasher.digest(), 'big')
        return hash_int % n  # Return scalar     

    def sign(self, msg: str, z: int, x: SigningKey):
        """
        create a ring signature for message m using the private key at index z. 

        Args:
            msg : message to sign
            z: index of the signer
            x: signing key of signer
        Returns: 
            signature [c, s[0], s[1], ..., s[n-1]]
        """
        sig = []
        # print(self.members[z].public)
        image = x * self.hash_point(self.public_keys[z])
        # image = self.hash_point(self.members[z].private) * self.hash_point(self.members[z].public)

        # generate glue value
        g = self.glue(msg)

        # generate random set of scalars (W and Q)
        W = []
        Q = []

        for i in range(len(self.public_keys)):

            if i != z: 
                w = random.randint(0, g)
                W.append(w)
            else: 
                W.append(0)
            q = random.randint(0,g)
            Q.append(q)

        L = []
        R = []
        for i in range(len(self.public_keys)):
            q = Q[i]
            w = W[i]
            pub = self.public_keys[i]
            if i != z: 
                l = q*self.curve.generator + w*pub
                r = q*self.hash_point(pub) + w*image
            else: 
                l = q*self.curve.generator
                r = q*self.hash_point(pub)

            L.append(l)
            R.append(r)

        c = self.hash_challenge(msg, L, R) #TODO

        cz = c
        for w in W: 
            cz -= w

        rz = Q[i] - cz*x

        # c values
        for i, w in enumerate(W):
            if i != z: 
                sig.append(w)
            else:
                sig.append(cz)

        # r values
        for i, q in enumerate(Q):
            if i != z: 
                sig.append(q)
            else:
                sig.append(rz)

        return sig, image

    def verify(self, msg: str, signature: list[int], image: int):
        """
        verify signature
        output boolean
        """

        mdpt = len(signature) // 2
        cs = signature[:mdpt]
        rs = signature[mdpt:]
    
        L = []
        R = []
        for i in range(len(cs)):
            c = cs[i]
            r = rs[i]
            pub = self.public_keys[i]

            l = r*self.curve.generator + c*pub
            r = r*self.hash_point(pub) + c*image

            L.append(l)
            R.append(r)

        h = self.hash_challenge(msg, L, R)

        print(f'\nh: {h}')
        print(f'sum(cs): {sum(cs)}')

        if sum(cs) == h:
            return True
        return False


class Agent: 
    def __init__(self, z: int, private: SigningKey, public: PointJacobi, ring: Ring):
        self.z = z
        self.private = private
        self.public = public
        self.ring = ring
    
    def sign(self, msg: str):

        return self.ring.sign(msg, self.z, self.private)
    
    def verify(self, msg: str, signature, image):

        return self.ring.verify(msg, signature, image)


if __name__ =="__main__":
    agents = []
    num_agents = 3
    
    # Choose a curve (this defines G automatically)
    curve = SECP256k1
    sign_keys = [SigningKey.generate(curve=SECP256k1) for i in range(num_agents)]
    priv_keys = [signing_key.privkey.secret_multiplier for signing_key in sign_keys]
    pub_keys = [signing_key.get_verifying_key().pubkey.point for signing_key in sign_keys]

    ring = Ring(public_keys=pub_keys, curve=curve)

    # initialize agents
    for i in range(num_agents):
        priv = priv_keys[i]
        pub = pub_keys[i]
        a = Agent(z=i, private=priv, public=pub, ring=ring)
        agents.append(a)
    
    
    ####
    msg1 = b"hello"
    msg2 = b"goodbye"

    a1 = agents[0]
    a2 = agents[1]
    sig1, image = a1.sign(msg1)
    print(f'\nsignature: \n{sig1}')

    valid1 = a2.verify(msg1, sig1, image)
    valid2 = a2.verify(msg2, sig1, image)

    print(f'\nmsg1 + sig1 valid: {valid1}')
    print(f'\nmsg2 + sig2 valid: {valid2}')

