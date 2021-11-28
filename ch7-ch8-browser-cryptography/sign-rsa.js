// This depends on a hex encoding library, such as arraybuffer-encoding from NPM
import {Encode} from 'arraybuffer-encoding/base64/standard'

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Message to sign, converted to a buffer
    const messageStr = 'Hello world!'
    const encoder = new TextEncoder()
    const message = encoder.encode(messageStr)

    // Generate a new 2048-bit key pair for calculating signatures with RSA
    const keyPair = await window.crypto.subtle.generateKey(
        // Options for the algorithm to use
        {
            // Name of the algorithm
            // This uses PCKS#1 v1.5
            // Another option is `RSA-PSS` for PSS
            name: 'RSASSA-PKCS1-v1_5',
            // Length of the RSA key (modulus), in bits
            modulusLength: 2048,
            // Public exponent: always use this static value (equivalent to 65537)
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            // Hashing function to use, e.g. SHA-256, SHA-384, SHA-512 (or SHA-1)
            hash: 'SHA-256'
        },
        // Key is non-extractable
        false,
        // Key can be used for calculating and verifying signatures
        ['sign', 'verify']
    )

    // Calculate the signature using RSA and PKCS#1 v1.5 padding
    // Use the private part of the key to sign
    const signature = await window.crypto.subtle.sign(
        // Name of the algorithm and RSA padding. This uses PKCS#1 v1.5
        // For RSA-PSS, you would pass a dictionary like this one instead:
        // `{name: 'RSA-PSS', saltLength: 32}`
        // The value of saltLength should match the length in bytes of the digest:
        // for example, when using SHA-256, the length is 32 (bytes)
        {name: 'RSASSA-PKCS1-v1_5'},
        // Signatures are calculated with the private key
        keyPair.privateKey,
        // Message to sign
        message
    )

    // Show the signature encoded as base64
    console.log('Signature:', Encode(signature))

    // Using the public part of the key, verify the signature
    const signatureValid = await window.crypto.subtle.verify(
        // Name of the algorithm and RSA padding
        // This is the same dictionary passed to the sign method
        {name: 'RSASSA-PKCS1-v1_5'},
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
  Signature: zWbJ7y40qQWCsZ7O+Q0dSsuKQ8JI9H/SbN7ZRrH55XA04EcDh1ThPD2cndMSCP52okSsxCSUatR2GjDCjq5ambuOuR/2ywfc/UNL2NVgYpUhe7cebe6vuqdk2b+lQ/KOWL2tYONyQxpiNX3NIFdi40/95kH0dyzBCgyvULPykf04Q3FP4Pf709wTJ+HF1QzRztu58s3kdVrrWjdC6i9BlI2QqVmkt7LK0WqbyLLn9k6sQmilEd1bzI/XXSKtdoIRPYamfo4Cw1PDulGnt08nqEr3gaJRHDVyn+yBCy/WLNZnzjZaqpjatlLW6VtIgUeEXPhbKp3sIhILWFxAEJ0Mwg==
  Signature valid? true
*/
