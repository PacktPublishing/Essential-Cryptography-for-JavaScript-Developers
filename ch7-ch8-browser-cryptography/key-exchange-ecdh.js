// Need to wrap this in an immediately-invoked function expression (IIFE) because of async code
;(async function() {
    // Generate a key pair for Alice (using the P-256 curve)
    const aliceKeyPair = await newKeyPair()

    // Generate a key pair for Bob  (using the P-256 curve)
    const bobKeyPair = await newKeyPair()

    // Alice calculates the shared key using her own private key and Bob's public key
    // The derived key will be used with AES-GCM to encrypt/decrypt data
    const aliceSharedKey = await deriveSecretKey(
        aliceKeyPair.privateKey,
        bobKeyPair.publicKey
    )

    // Bob calculates the shared key using his own private key Alice's public key
    // The derived key will be used with AES-GCM to encrypt/decrypt data
    const bobSharedKey = await deriveSecretKey(
        bobKeyPair.privateKey,
        aliceKeyPair.publicKey
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
 * @param {CryptoKey} privateKey Private part of our own key
 * @param {CryptoKey} publicKey Public part of the other person's key
 * @returns {Promise<CryptoKey>} A new AES-256-GCM key in a CryptoKey object
 */
function deriveSecretKey(privateKey, publicKey) {
    return window.crypto.subtle.deriveKey(
        {
            // Specify this is an ECDH exchange
            name: 'ECDH',
            // Use the other person's public key in "algorithm.public"
            public: publicKey
        },
        // Pass our private key as "baseKey"
        privateKey,
        // The remaining parameters are options for the resulting key
        // First, set the algorithm for the resulting key to AES-GCM and with 256 bits in length
        {name: 'AES-GCM', length: 256},
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
        // Key can be used for deriving new keys only
        ['deriveKey']
    )
}
