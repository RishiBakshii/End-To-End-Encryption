import crypto from 'crypto';

// GCM: Galois/Counter Mode

// Create ECDH (Elliptic Curve Diffie-Hellman) key exchange objects for Alice and Bob using the 'secp256k1' curve
const alice = crypto.createECDH('secp256k1');
const bob = crypto.createECDH('secp256k1');

// Generate public and private keys for Alice and Bob
alice.generateKeys();
bob.generateKeys();

// Compute shared secrets using the public keys of the opposite party
const aliceSharedKey = alice.computeSecret(bob.getPublicKey('base64'), 'base64', 'hex');
const bobSharedKey = bob.computeSecret(alice.getPublicKey('base64'), 'base64', 'hex');

// Verify that both Alice and Bob have the same shared secret key
console.log(aliceSharedKey === bobSharedKey);  // True if the keys match

const MESSAGE = 'this is a random message...';

// Generate an Initialization Vector (IV) for AES-GCM encryption
const IV = crypto.randomBytes(16);

// Create a cipher object using the shared secret key, IV, and AES-256-GCM mode
const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(aliceSharedKey, 'hex'), IV);

// Encrypt the message
let encrypted = cipher.update(MESSAGE, 'utf-8', 'hex');
encrypted += cipher.final('hex');

// Get the authentication tag to ensure the integrity and authenticity of the encrypted message
const authTag = cipher.getAuthTag().toString('hex');

// Display the IV, encrypted message, and authentication tag
console.table({
    IV: IV.toString('hex'),
    encrypted,
    authTag,
});

// Create a payload that concatenates the IV, encrypted message, and authentication tag, then encode it in base64
const payload = IV.toString('hex') + encrypted + authTag;
const payloadBase64 = Buffer.from(payload, 'hex').toString('base64');
console.log(payloadBase64);

// Bob's side: Decode the payload from base64 back to hex
const bobPayload = Buffer.from(payloadBase64, 'base64').toString('hex');

// Extract the IV, encrypted message, and authentication tag from the payload
const bobIv = bobPayload.substring(0, 32);
const bobEncryptedMessage = bobPayload.substring(32, bobPayload.length - 32);
const bobAuthTag = bobPayload.substring(bobPayload.length - 32);

// Display Bob's extracted IV, encrypted message, and authentication tag
console.table({
    bobIv,
    bobEncryptedMessage,
    bobAuthTag,
});

try {
    // Create a decipher object using the shared secret key, IV, and AES-256-GCM mode
    const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(bobSharedKey, 'hex'), Buffer.from(bobIv, 'hex'));

    // Set the authentication tag to verify the integrity and authenticity of the message
    decipher.setAuthTag(Buffer.from(bobAuthTag, 'hex'));

    // Decrypt the encrypted message
    let decrypted = decipher.update(bobEncryptedMessage, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');

    // Display the decrypted message
    console.log('Decrypted message:', decrypted);
} catch (error) {
    // Log any errors that occur during the decryption process
    console.log(error);
}


// GCM (Galois/Counter Mode):

// GCM is an encryption mode used with block ciphers like AES (Advanced Encryption Standard).
// It provides both confidentiality and authenticity of the data.
// GCM mode is suitable for authenticated encryption with associated data (AEAD), meaning it not only encrypts the data but also ensures its integrity and authenticity.


// Cipher:

// In cryptography, a cipher is an algorithm used for encryption and decryption.
// In the code, crypto.createCipheriv('aes-256-gcm', key, iv) creates a cipher object for encryption using the AES-256-GCM algorithm.
// The cipher object provides methods like update() to encrypt data incrementally and final() to finalize the encryption process.


// IV (Initialization Vector):

// An initialization vector (IV) is a fixed-size random or pseudorandom value used in cryptographic algorithms.
// It's used along with the encryption key to initialize the encryption process.
// The IV ensures that each encrypted message produces a unique ciphertext even when the same plaintext is encrypted multiple times.
// In the code, crypto.randomBytes(16) generates a 16-byte random IV for AES-GCM encryption.

// Auth Tag (Authentication Tag):

// The authentication tag, also known as the MAC (Message Authentication Code), is a small piece of data appended to the encrypted message.
// It's used to verify the integrity and authenticity of the encrypted data.
// In GCM mode, the authentication tag is generated during encryption and verified during decryption.
// If the encrypted message is tampered with or modified, the authentication tag won't match, indicating that the data has been compromised.
// In the code, cipher.getAuthTag() retrieves the authentication tag after encryption, and decipher.setAuthTag() sets the authentication tag during decryption.