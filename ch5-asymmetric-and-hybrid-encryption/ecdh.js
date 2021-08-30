// Import the required modules
const crypto = require('crypto')

// Promisify the crypto.generateKeyPair method
const generateKeyPair = require('util').promisify(crypto.generateKeyPair)

// Need to wrap this in an immediately-invoked function expression (IIFE) because of async code
;(async function() {
    // Generate a key pair for Alice (using the P-256 curve)
    // Then export the public key as PEM
    const aliceKeyPair = await generateKeyPair('ec', {
        namedCurve: 'prime256v1'
    })
    const alicePublicKeyPem = aliceKeyPair.publicKey.export({
        type: 'spki',
        format: 'pem'
    })

    // Generate a key pair for Bob  (using the P-256 curve)
    // Then export the public key as PEM
    const bobKeyPair = await generateKeyPair('ec', {
        namedCurve: 'prime256v1'
    })
    const bobPublicKeyPem = bobKeyPair.publicKey.export({
        type: 'spki',
        format: 'pem'
    })

    // Alice calculates the shared secret using her own private key and Bob's public key
    const aliceSharedSecret = crypto.diffieHellman({
        publicKey: crypto.createPublicKey(bobPublicKeyPem),
        privateKey: aliceKeyPair.privateKey
    })

    // Bob calculates the shared secret using his own private key Alice's public key
    const bobSharedSecret = crypto.diffieHellman({
        publicKey: crypto.createPublicKey(alicePublicKeyPem),
        privateKey: bobKeyPair.privateKey
    })

    // Both Alice and Bob have derived the same shared secret: the output should be identical
    console.log(aliceSharedSecret.toString('hex'))
    console.log(bobSharedSecret.toString('hex'))
})()
