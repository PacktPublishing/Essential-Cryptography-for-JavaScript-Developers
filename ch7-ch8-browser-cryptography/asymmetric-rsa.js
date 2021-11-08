// This depends on a hex encoding library, such as arraybuffer-encoding from NPM
import {Encode} from 'arraybuffer-encoding/base64/standard'

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Message to encrypt
    const plaintextMessage = 'Hello world!'

    // Generate a new 2048-bit key pair for encryption with RSA-OAEP
    const keyPair = await window.crypto.subtle.generateKey(
        // Options for the algorithm to use
        {
            // Name of the algorithm
            name: 'RSA-OAEP',
            // Length of the RSA key (modulus), in bits
            modulusLength: 2048,
            // Public exponent: always use this static value (equivalent to 65537)
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            // Hashing function to use, e.g. SHA-256, SHA-384, SHA-512 (or SHA-1)
            hash: 'SHA-256'
        },
        // Key is non-extractable
        false,
        // Key can be used for encryption/decryption only
        ['encrypt', 'decrypt']
    )

    // Convert the plaintext message to a buffer (Uint8Array)
    const encoder = new TextEncoder()
    const plaintext = encoder.encode(plaintextMessage)

    // Encrypt the plaintext using RSA-OAEP and the public part of the key
    const encrypted = await window.crypto.subtle.encrypt(
        // Set the algorithm to RSA-OAEP
        {name: 'RSA-OAEP'},
        // Encrypt using the public part of the key
        keyPair.publicKey,
        // Plaintext message as buffer
        plaintext
    )

    // Print the ciphertext encoded as base64
    console.log(
        'encrypted:',
        Encode(encrypted)
    )

    // Decrypt the ciphertext using RSA-OAEP and the private part of the key
    const decrypted = await window.crypto.subtle.decrypt(
        // Set the algorithm to RSA-OAEP
        {name: 'RSA-OAEP'},
        // Decrypt using the private part of the key
        keyPair.privateKey,
        // Ciphertext
        encrypted
    )

    // The value of decrypted is a buffer, so we need to decode it to a UTF-8 string
    const decoder = new TextDecoder('utf-8')
    console.log(
        'decrypted:',
        decoder.decode(decrypted)
    )
})()

/*
Example result (will be different every time):
  encrypted: shJWkXfhsRa2MnYr96/wvSMemv2Tu5XUjS8MzAHV/TcvV3X8c+sBojMWWsKwGvgM7NJr4l5vdOJAMdNh41GS3SwjiZth/Ok/9mZWQ2n47Hh/A2J2gC9Uineke0R9ZxZQrVQjA1ScfaE+pgs6nm5BFAQt0/V4/eFAZRoru53jXS4o/PruFTBM1O/iwb7+FAEmC9I71R6FDdQ3L/mXHd1TamfwJB19EmFhkv50UXX7ReenmnTI4k1KXAcqIg4+1dsdcvMdNqzsKBPSXA/A/p1+GuPkdzFqRVzo3wuOUNcL+prdkWkgGR8LQ1wqSUQm9CSTmOrPnmLOk9Zz3P79t+X0oQ==
  decrypted: Hello world!
*/
