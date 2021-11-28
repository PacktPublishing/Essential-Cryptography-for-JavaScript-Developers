// Need to wrap this in an immediately-invoked function expression (IIFE) because of async code
;(async function() {
    // Generate a key pair for Alice (using the P-256 curve)
    const aliceKeyPair = await newKeyPair()

    // Generate a key pair for Bob  (using the P-256 curve)
    const bobKeyPair = await newKeyPair()

    // Generate a random, 16-byte salt for deriving the key
    const salt = new Uint8Array(16)
    window.crypto.getRandomValues(salt)

    // Alice calculates the shared key using her own private key and Bob's public key
    // The derived key will be used with AES-GCM to encrypt/decrypt data
    const aliceSharedKey = await deriveSecretKey(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey,
        salt
    )

    // Bob calculates the shared key using his own private key Alice's public key
    // The derived key will be used with AES-GCM to encrypt/decrypt data
    const bobSharedKey = await deriveSecretKey(
        bobKeyPair.privateKey,
        aliceKeyPair.publicKey,
        salt
    )

    // aliceSharedKey and bobSharedKey should contain the same key
    // If the key were exportable, you could export them to see that they're indeed equal, for example with:
    /*console.log(
        await window.crypto.subtle.exportKey('jwk', aliceSharedKey),
        await window.crypto.subtle.exportKey('jwk', bobSharedKey),
    )*/
})()

/**
 * Derive an AES-256-GCM key performing an ECDH key exchange.
 * This function is modified to use deriveBits to perform the ECDH exchange and then "stretch" the derived data with SHA-256 and a salt, to make it more uniform.
 * @param {CryptoKey} privateKey Private part of our own key
 * @param {CryptoKey} publicKey Public part of the other person's key
 * @param {ArrayBufferLike} salt Salt to be used during the key derivation
 * @returns {Promise<CryptoKey>} A new AES-256-GCM key in a CryptoKey object
 */
async function deriveSecretKey(privateKey, publicKey, salt) {
    // First, derive a sequence of bytes (in an ArrayBuffer) by performing an ECDH exchange
    const ecdhResult = await window.crypto.subtle.deriveBits(
        {
            // Specify this is an ECDH exchange
            name: 'ECDH',
            // Use the other person's public key in "algorithm.public"
            public: publicKey
        },
        // Pass our private key as "baseKey"
        privateKey,
        // Request 256 bits (32 bytes) of data
        256
    )

    // Append the salt to the ECDH result
    const base = new Uint8Array([
        ...new Uint8Array(ecdhResult),
        ...salt
    ])

    // Stretch the result of the ECDH exchange with the salt by calculating a SHA-256 hash
    const rawKey = await window.crypto.subtle.digest('SHA-256', base)

    // Create a CryptoKey object from the rawKey data, for use with AES-256-GCM
    return window.crypto.subtle.importKey(
        // Import the key in "raw" format
        'raw',
        // Key data
        rawKey,
        // Set the algorithm for the resulting key to AES-GCM
        {name: 'AES-GCM'},
        // Make the resulting key not extractable
        false,
        // Usages for the resulting key
        ['encrypt', 'decrypt']
    )
}

/**
 * Generate a new Elliptic Curve key pair, creating a new random P-256 key every time. The key can be used to perform ECDH key exchanges.
 * @returns {Promise<CryptoKeyPair>} Key pair object
 */
 function newKeyPair() {
    // Generate a new P-256 key pair for ECDH
    return window.crypto.subtle.generateKey(
        // Options for the algorithm to use
        {
            // Name of the algorithm: ECDH for a key exchange
            name: 'ECDH',
            // Name of the curve: P-256 is the same curve as prime256v1 in Node.js
            namedCurve: 'P-256'
        },
        // Key is non-extractable
        false,
        // Key can be used for deriving bits only
        ['deriveBits']
    )
}
