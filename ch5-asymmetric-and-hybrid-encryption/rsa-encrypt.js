// Import the required modules
const crypto = require('crypto')
const fs = require('fs')

// Promisify the fs.readFile method
const readFile = require('util').promisify(fs.readFile)

/**
 * Encrypts a message using RSA and the given public key
 * @param {crypto.KeyObject} publicKey Public key object
 * @param {string} plaintext The message to encrypt, as a string
 * @returns {Buffer} The encrypted message
 */
function rsaEncrypt(publicKey, plaintext) {
    // Encrypt the message
    return crypto.publicEncrypt(
        {
            // Public key
            key: publicKey,
            // Padding to use; options include:
            // - `RSA_PKCS1_OAEP_PADDING` for OAEP
            // - `RSA_PKCS1_PADDING` for PKCS#1 v1.5
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            // When using OAEP, we can specify the hashing function to use, which is SHA1 by default
            oaepHash: 'sha256'
        },
        plaintext
    )
}

/**
 * Decrypts the encrypted message using RSA and the given private key
 * @param {crypto.KeyObject} privateKey Private key object
 * @param {Buffer} message The encrypted message
 * @returns {Buffer} The decrypted message
 */
function rsaDecrypt(privateKey, message) {
    // Decrypt the ciphertext
    return crypto.privateDecrypt(
        {
            // Private key
            key: privateKey,
            // Padding constant used when encrypting the message before
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            // If using OAEP, we should specify the hashing function used too (defaults to SHA1 if unspecified)
            oaepHash: 'sha256'
        },
        message
    )
}

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async function() {
    // Message to encrypt
    const plaintext = 'Hello world!'

    // Asymmetric encryption is performed with the public key
    // In here we're creating a crypto.KeyObject containing the public key
    // Because the public key can be generated from the private one too, we could also load 'private.pem' instead of 'public.pem' here
    const publicKeyObject = crypto.createPublicKey(
        await readFile('public.pem')
    )

    // Encrypt the message using RSA with the public key loaded above
    const encrypted = rsaEncrypt(publicKeyObject, plaintext)

    // Show the result as a base64-encoded string
    console.log('Encrypted message:', encrypted.toString('base64'))

    // Load the private key from the 'private.pem' file, which we'll use to decrypt the encrypted message
    const privateKeyObject = crypto.createPrivateKey(
        await readFile('private.pem')
    )

    // Decrypt the message using the RSA private key loaded above
    const decrypted = rsaDecrypt(privateKeyObject, encrypted)

    // Show the result
    console.log('Decrypted message:', decrypted.toString('utf8'))
})()

