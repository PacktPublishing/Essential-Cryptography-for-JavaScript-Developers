// This depends on a hex encoding library, such as arraybuffer-encoding from NPM
import {Encode} from 'arraybuffer-encoding/base64/standard'

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Message to sign, converted to a buffer
    const messageStr = 'Hello world!'
    const encoder = new TextEncoder()
    const message = encoder.encode(messageStr)

    // Generate a new P-256 key pair for calculating signatures with ECDH
    const keyPair = await window.crypto.subtle.generateKey(
        // Options for the algorithm to use
        {
            // Name of the algorithm: ECDSA for digital signatures
            name: 'ECDSA',
            // Name of the curve: P-256 is the same curve as prime256v1 in Node.js
            namedCurve: 'P-256'
        },
        // Key is non-extractable
        false,
        // Key can be used for calculating and verifying signatures
        ['sign', 'verify']
    )

    // Calculate the signature using ECDSA
    // Use the private part of the key to sign
    const signature = await window.crypto.subtle.sign(
        // Options for the algorithm
        {
            // Name of the algorithm
            name: 'ECDSA',
            // Hashing function to use, e.g. SHA-256, SHA-384, SHA-512 (or SHA-1)
            hash: 'SHA-256'
        },
        // Signatures are calculated with the private key
        keyPair.privateKey,
        // Message to sign
        message
    )

    // Show the signature encoded as base64
    console.log('Signature:', Encode(signature))

    // Using the public part of the key, verify the signature
    const signatureValid = await window.crypto.subtle.verify(
        // Options for the algorithm
        {
            // Name of the algorithm
            name: 'ECDSA',
            // Hashing function to use, e.g. SHA-256, SHA-384, SHA-512 (or SHA-1)
            hash: 'SHA-256'
        },
        // Public key, used to verify the signature
        keyPair.publicKey,
        // Signature (as a buffer)
        signature,
        // Original message that was signed
        message
    )

    // Show the result
    console.log('Signature valid?', signatureValid)
})()

/*
Example result (will be different every time):
  Signature: lzq1qfE+0GUREv0Zi0vSOhT0w2ucCzfJMjw5ANSzqKovNOJXMGEXnV7f17WV1D6uBEf0ndK5ECdqPkdpJDPYZg==
  Signature valid? true
*/
