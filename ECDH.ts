import crypto from 'crypto'

// it is 256 bit long is as secure as a 3072 bit long shared secret key genereated using the traditionla diffie hellman
// equation  = y2 = x3 + ax + b
// in diffie helman we have p and g 
// here we have a and b
// and depennding upon a and b the shape of the curve changes


// logging the curves
console.log(crypto.getCurves());

// we will be using this curve 'secp256k1', Bitcoin also uses this curve

// we should use the same curves otherwise the shared secret wont be generated
const alice = crypto.createECDH("secp256k1")
const bob = crypto.createECDH("secp256k1")

// generating public and private keys for alice and bob
alice.generateKeys()
bob.generateKeys()

// now here comes the part where we will exchange the public keys
// typical way of transimitting public keys is in base64 format
const alicePublicKeyBase64 = alice.getPublicKey('base64')
const bobPublicKeyBase64 = bob.getPublicKey('base64')

// Computing Shared Secret
// Both Alice and Bob compute the shared secret using each other's public keys. The format of the shared key is hex.
const aliceSharedKey = alice.computeSecret(bobPublicKeyBase64,'base64','hex')
const bobSharedKey = bob.computeSecret(alicePublicKeyBase64,'base64','hex')

// Check if the shared keys match, which they should if everything is done correctly.
console.log(aliceSharedKey === bobSharedKey)
console.log(aliceSharedKey);
console.log(bobSharedKey);

// as 1 character of hexa decimal value is equal to 4 bits 
// so the final output of the length will be 256 bits
console.log(aliceSharedKey.length * 4);



// Summary
// ECDH is a key exchange protocol similar to traditional Diffie-Hellman but uses elliptic curve cryptography.
// It offers equivalent or better security with shorter key lengths, making it more efficient.
// In traditional Diffie-Hellman, you use a large prime number p and a base g.
// In ECDH, you use parameters a and b that define the elliptic curve equation y2 = x3 + ax + b
// A 256-bit key in ECDH provides security equivalent to a 3072-bit key in traditional Diffie-Hellman due to the properties of elliptic curves.
// This shared secret can then be used with symmetric encryption algorithms like AES for secure communication.
