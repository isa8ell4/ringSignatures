import os, hashlib, random, Crypto.PublicKey.RSA
import sys
from functools import reduce
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.curves import Curve
from ecdsa.ellipticcurve import Point, PointJacobi
class Agent: 
    def __init__(self, private: SigningKey, public: PointJacobi):
        self.private = private
        self.public = public


class Ring: 
    def __init__(self, members: list[Agent], curve: Curve):
        self.members = members
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

    def sign(self, msg: str, z: int):
        """
        create a ring signature for message m using the private key at index z. 

        Args:
            msg : message to sign
            z: index of the signer
        Returns: 
            signature [c, s[0], s[1], ..., s[n-1]]
        """
        sig = []
        print(self.members[z].public)
        image = self.members[z].private * self.hash_point(self.members[z].public)
        # image = self.hash_point(self.members[z].private) * self.hash_point(self.members[z].public)

        # generate glue value
        g = self.glue(msg)

        # generate random set of scalars (W and Q)
        W = []
        Q = []

        for i in range(len(self.members)):

            if i != z: #TODO
                w = random.randint(0, g)
                W.append(w)
            else: 
                W.append(0)
            q = random.randint(0,g)
            Q.append(q)

        L = []
        R = []
        for i in range(len(self.members)):
            q = Q[i]
            w = W[i]
            pub = self.members[i].public
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

        rz = Q[i] - cz*self.members[i].private

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
            pub = self.members[i].public

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

if __name__ =="__main__":
    agents = []
    num_agents = 3
    
    # Choose a curve (this defines G automatically)
    curve = SECP256k1
    # print(type(curve))

    # initialize agents
    for i in range(num_agents):

        # G is implicit - when you do operations, the library uses it
        signing_key = SigningKey.generate(curve=SECP256k1)
        private_key = signing_key.privkey.secret_multiplier
        public_key = signing_key.get_verifying_key().pubkey.point 
        # print(f'\npriv:{type(private_key)}\n\t{private_key}')
        # print(f'pub:{type(public_key)}\n\t{public_key}')
        a = Agent(private=private_key, public=public_key)
        agents.append(a)
    
    ring = Ring(members=agents, curve=curve)

    ####
    msg1 = b"hello"
    msg2 = b"goodbye"

    a1 = agents[0]
    sig1, image = ring.sign(msg1, 0)
    print(f'\nsignature: \n{sig1}')

    valid1 = ring.verify(msg1, sig1, image)
    valid2 = ring.verify(msg2, sig1, image)

    print(f'\nmsg1 + sig1 valid: {valid1}')
    print(f'\nmsg2 + sig2 valid: {valid2}')

