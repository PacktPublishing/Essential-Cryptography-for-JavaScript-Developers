// Import the required modules
const crypto = require('crypto')
const fs = require('fs')

/**
 * Calculates the digital signature of a message using the given Ed25519 private key.
 * @param {crypto.KeyObject} privateKey Private key object
 * @param {Buffer|string} message Message to sign
 * @returns {Buffer} The signature of the message
 */
function ed25519Sign(privateKey, message) {
    // Calculate the digital signature of the message using the private key
    return crypto.sign(
        // Automatically determine the algorithm for hashing when using Ed25519
        null,
        // Message to sign
        message,
        // Private key used for calculating the signature
        privateKey
    )
}

/**
 * Verifies the digital signature of a message using the given Ed25519 public key (corresponding to the private key which was used to generate the signature).
 * @param {crypto.KeyObject} publicKey Public key object
 * @param {Buffer|string} message Original message that was signed
 * @param {Buffer} signature The signature of the message to verify
 * @returns {boolean} Returns true if the signature is valid for the message
 */
function ed25519Verify(publicKey, message, signature) {
    // Verify if the digital signature of the message matches using the public key
    return crypto.verify(
        // Automatically determine the algorithm for hashing when using Ed25519
        null,
        // Original message that was signed
        message,
        // Public key used to verify the signature
        publicKey,
        // Signature to verify
        signature
    )
}

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async function() {
    // Message to sign
    const message = 'I owe Clare $100'

    // Digital signatures are calculated with a private key
    // With this we're creating a crypto.KeyObject containing the private key (loaded from file)
    const privateKeyObject = crypto.createPrivateKey(
        fs.readFileSync('private-ed25519.pem')
    )

    // Calculate the signature using RSA and the private key
    const signature = ed25519Sign(privateKeyObject, message)

    // Show the result as a base64-encoded string
    console.log('Message:', message)
    console.log('Signature:', signature.toString('base64'))

    // Load the public key from file, which we'll use to verify the signature
    const publicKeyObject = crypto.createPublicKey(
        fs.readFileSync('public-ed25519.pem')
    )

    // Verify the signature
    const signatureVerified = ed25519Verify(publicKeyObject, message, signature)

    // Show the result
    console.log('Signature valid:', signatureVerified)
})()
