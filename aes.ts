import aes256 from 'aes256'
import crypto from 'crypto'


// Create ECDH objects for Alice and Bob
const alice = crypto.createECDH("secp256k1")
const bob = crypto.createECDH("secp256k1")


// Generate public and private keys for Alice and Bob
alice.generateKeys()
bob.generateKeys()


// Compute shared secret for both Alice and Bob
const aliceSharedKey = alice.computeSecret(bob.getPublicKey('base64'),'base64','hex')
const bobSharedKey = bob.computeSecret(alice.getPublicKey('base64'),'base64','hex')

// Ensure the shared secrets match
console.log("Shared keys match: ", aliceSharedKey === bobSharedKey);

// Message to be encrypted
const message = 'this is some random message...';

// Encrypt the message using Alice's shared key
const encrypted = aes256.encrypt(aliceSharedKey, message);

// Decrypt the message using Bob's shared key
const decrypted = aes256.decrypt(bobSharedKey, encrypted);

console.log("original message  : ",message);
console.log("encrypted message : ",encrypted);
console.log("decrypted message : ",decrypted);



