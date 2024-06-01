import crypto from 'crypto'
import aes256 from 'aes256'

// Create Diffie-Hellman key exchange objects for Alice and Bob using the "modp15" group
const alice = crypto.getDiffieHellman('modp15');
const bob = crypto.getDiffieHellman('modp15');

// Generate keys for Alice and Bob
alice.generateKeys();
bob.generateKeys();

// Compute shared secrets
const aliceSecret = alice.computeSecret(bob.getPublicKey(),null,'hex');
const bobSecret = bob.computeSecret(alice.getPublicKey(), null, 'hex');

// Check if the shared secrets match
console.log(aliceSecret === bobSecret);



// Elliptic curve diffie hellman (ECDH)

// console.log(crypto.getCurves());
const alice = crypto.createECDH("secp256k1")
alice.generateKeys()

const bob = crypto.createECDH("secp256k1")
bob.generateKeys()

const alicePublicKeyBase64 = alice.getPublicKey().toString("base64")
const bobPublicKeyBase64 = bob.getPublicKey().toString("base64")

const aliceSharedKey = alice.computeSecret(bobPublicKeyBase64,'base64','hex')
const bobSharedKey = bob.computeSecret(alicePublicKeyBase64,'base64','hex')

// console.log(aliceSharedKey===bobSharedKey);
// console.log(aliceSharedKey);


// const message = "this is some random message"

// const encrypted = aes256.encrypt(aliceSharedKey,message)
// console.log("encrypted message :",encrypted);

// console.log('decrypted message',aes256.decrypt(bobSharedKey,encrypted));

const MESSAGE = "this is some random message..."


const IV = crypto.randomBytes(16)
const cipher = crypto.createCipheriv('aes-256-gcm',Buffer.from(aliceSharedKey,'hex'),IV)

let encrypted = cipher.update(MESSAGE,'utf-8','hex')
encrypted += cipher.final('hex')

const authTag = cipher.getAuthTag().toString("hex")

console.table({
    IV:IV.toString("hex"),
    encrypted:encrypted,
    authTag:authTag
})

const payload = IV.toString("hex") + encrypted + authTag
const payload64 = Buffer.from(payload,'hex').toString("base64")

console.log(payload64);


// bob will do from here
const bobPayload = Buffer.from(payload64,'base64').toString("hex")

const bobIv = bobPayload.substring(0,32)
const bobEncrypted = bobPayload.substring(32,bobPayload.length -32 -32)
const bobAuthTag = bobPayload.substring(bobPayload.length - 32,32)

console.table({
    bobIv:bobIv,
    bobEncrypted:bobEncrypted,
    bobAuthTag:bobAuthTag
});


try {
    const decipher = crypto.createDecipheriv("aes-256-gcm",Buffer.from(bobSharedKey,'hex'),Buffer.from(bobIv,'hex'))

    decipher.setAuthTag(Buffer.from(bobAuthTag,'hex'))

    let decryptedMessage = decipher.update(bobEncrypted,'hex','utf-8')
    decryptedMessage+= decipher.final("utf-8")

    console.log("Decrypted Message: ",decryptedMessage);

} catch (error) {
    console.log(error);
}
