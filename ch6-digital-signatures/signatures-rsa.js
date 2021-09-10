// Import the required modules
const crypto = require('crypto')
const fs = require('fs')

/**
 * Calculates the digital signature of a message using the given RSA private key.
 * As configured, this function uses SHA-256 for hashing and RSA-PSS for padding with the default options in Node.js.
 * @param {crypto.KeyObject} privateKey Private key object
 * @param {Buffer|string} message Message to sign
 * @returns {Buffer} The signature of the message
 */
function rsaSign(privateKey, message) {
    // Calculate the digital signature of the message using the private key
    return crypto.sign(
        // Algorithm used for hashing: we'll use SHA-256
        'sha256',
        // Message to sign
        message,
        {
            // Private key used for calculating the signature
            key: privateKey,
            // Padding to use; options include:
            // - `RSA_PKCS1_PSS_PADDING` for PSS
            // - `RSA_PKCS1_PADDING` for PKCS#1 v1.5
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING
        }
    )
}

/**
 * Verifies the digital signature of a message using the given RSA public key (corresponding to the private key which was used to generate the signature).
 * @param {crypto.KeyObject} publicKey Public key object
 * @param {Buffer|string} message Original message that was signed
 * @param {Buffer} signature The signature of the message to verify
 * @returns {boolean} Returns true if the signature is valid for the message
 */
function rsaVerify(publicKey, message, signature) {
    // Verify if the digital signature of the message matches using the public key
    return crypto.verify(
        // Algorithm that was used for hashing
        'sha256',
        // Original message that was signed
        message,
        {
            // Public key used to verify the signature
            key: publicKey,
            // Padding that was used when calculating the signature
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING
        },
        // Signature to verify
        signature
    )
}

/* Example usage */

// Message to sign
const message = 'I owe Clare $100'

// Digital signatures are calculated with a private key
// With this we're creating a crypto.KeyObject containing the private key (loaded from file)
const privateKeyObject = crypto.createPrivateKey(
    fs.readFileSync('private.pem')
)

// Calculate the signature using RSA and the private key
const signature = rsaSign(privateKeyObject, message)

// Show the result as a base64-encoded string
console.log('Message:', message)
console.log('Signature:', signature.toString('base64'))

// Load the public key from file, which we'll use to verify the signature
const publicKeyObject = crypto.createPublicKey(
    fs.readFileSync('public.pem')
)

// Verify the signature
const signatureVerified = rsaVerify(publicKeyObject, message, signature)

// Show the result
console.log('Signature valid:', signatureVerified)
