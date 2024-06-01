import crypto from 'crypto'

// 3072-bit MODP Group

//    This group is assigned id 15.

//    This prime is: 2^3072 - 2^3008 - 1 + 2^64 * { [2^2942 pi] + 1690314 }

//    Its hexadecimal value is:

//       FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
//       29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
//       EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
//       E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
//       EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
//       C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
//       83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
//       670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
//       E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
//       DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
//       15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
//       ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
//       ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
//       F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
//       BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
//       43DB5BFC E0FD108E 4B82D120 A93AD2CA FFFFFFFF FFFFFFFF

//    The generator is: 2.


// Implementation

// Create Diffie-Hellman key exchange objects for Alice and Bob using the "modp15" group
const alice = crypto.getDiffieHellman('modp15');
const bob = crypto.getDiffieHellman('modp15');

// 
const alicePrime = alice.getPrime().toString('hex')
const bobPrime = alice.getPrime().toString("hex")

console.log("alicePrime : ",alicePrime)
console.log('\n');
console.log("bobPrime : ",bobPrime)

// Generate keys for Alice and Bob
// This generates the public and private keys for both Alice and Bob.
alice.generateKeys();
bob.generateKeys();

// Computes the shared secret using their own private key and each others public key
const aliceSecret = alice.computeSecret(bob.getPublicKey(),null,'hex');
const bobSecret = bob.computeSecret(alice.getPublicKey(), null, 'hex');

// Check if the shared secrets match
// This confirms that both Alice and Bob have derived the same shared secret.
console.log(aliceSecret === bobSecret);


// Summary

// Alice and Bob each generate their public and private keys based on the shared prime from the modp15 group.
// They compute a shared secret using their private key and the other party's public key.
// The computed shared secrets for Alice and Bob should match, demonstrating the successful key exchange.