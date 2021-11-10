// This depends on a hex encoding library, such as arraybuffer-encoding from NPM
import {Encode} from 'arraybuffer-encoding/base64/standard'

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Message to encrypt, converted to a buffer
    const plaintextMessage = 'Hello world!'
    const encoder = new TextEncoder()
    const plaintext = encoder.encode(plaintextMessage)

    // Obtain a RSA key pair, containing the public and private keys
    const keyPair = await newRSAKeyPair()

    // Encrypt the message using hybrid encryption, and obtain both the ciphertext (encrypted message) and the wrapped key (encrypted key)
    const {wrappedKey, encrypted} = await hybridEncrypt(keyPair.publicKey, plaintext)

    // You will need to transmit to the other party both the ciphertext and the wrapped key
    // Showing them here encoded as base64
    console.log('Encrypted message and wrapped key', {
        encrypted: Encode(encrypted),
        wrappedKey: Encode(wrappedKey),
    })

    // Decrypt the encrypted message using the private key and the wrapped key
    const decrypted = await hybridDecrypt(keyPair.privateKey, wrappedKey, encrypted)

    // Show the result, converted to string
    const decoder = new TextDecoder('utf-8')
    console.log('Decrypted message:',
        decoder.decode(decrypted)
    )
})()

/*
Example result (will be different every time):
  Encrypted message and wrapped key {
    encrypted: '1gE8jzKEpCfv86jysJmEXYNY+/5o1w2uWkpChA/Y7IZfOpXkfGQLCzrXWlk=',
    wrappedKey: 'AQIb7eaEpy4ZSuUc3rwXOtjl/FEjov/AATB6S6Y4jiLFucbUt5…n51+j2FY7aFqHf8TjKROjki6aQ6VUXeiqV90V6dEP6HLFKXs='
  }
  Decrypted message: Hello world!
*/

/**
 * Encrypts a message using hybrid encryption (RSA+AES) and the given public key.
 * Returns an object containing the encrypted message as well as the wrapped (encrypted) symmetric key.
 * @param {CryptoKey} publicKey Public key object
 * @param {ArrayBufferLike} plaintext The message to encrypt, as a buffer
 * @returns { Promise<{encrypted: Uint8Array, wrappedKey: ArrayBuffer}> } Object containing the encrypted message and the wrapped key
 */
async function hybridEncrypt(publicKey, plaintext) {
    // Generate a new 256-bit key for using with AES-GCM
    const symmetricKey = await window.crypto.subtle.generateKey(
        // Algorithm the key will be used for and size
        {name: 'AES-GCM', length: 256},
        // Key is extractable (will be exported wrapped)
        true,
        // This key object can be used for encryption only
        ['encrypt']
    )

    // Encrypt the plaintext using the symmetric key
    const encrypted = await symmetricEncrypt(symmetricKey, plaintext)

    // Wrap (encrypt) the symmetric key using RSA and the public key
    const wrappedKey = await rsaKeyWrap(publicKey, symmetricKey)

    // Return an object with the encrypted message and the wrapped key
    return {encrypted, wrappedKey}
}

/**
 * Decrypts an encrypted message using hybrid encryption (RSA+AES) and a symmetric key encrypted with a RSA key.
 * @param {CryptoKey} privateKey Private key object
 * @param {ArrayBufferLike} wrappedKey Wrapped symmetric key
 * @param {ArrayBufferLike} message The encrypted message, as a buffer
 * @returns {Promise<ArrayBufferLike>} The decrypted message, as a buffer
 */
 async function hybridDecrypt(privateKey, wrappedKey, message) {
    // Unwrap (decrypt) the symmetric key using RSA and the private key
    const symmetricKey = await rsaKeyUnwrap(privateKey, wrappedKey)

    // Decrypt the message using the symmetric key
    const decrypted = await symmetricDecrypt(symmetricKey, message)

    // Return the decrypted message
    return decrypted
}

/**
 * Encrypts the plaintext message using the given key with AES-256-GCM
 * @param {CryptoKey} symmetricKey The 256-bit symmetric key that can be used to encrypt data with AES-GCM
 * @param {ArrayBufferLike} plaintext The message to encrypt, as a buffer
 * @returns {Promise<Uint8Array>} The result is the concatenation of the IV, the ciphertext, and the AES-GCM authentication tag
 */
async function symmetricEncrypt(symmetricKey, plaintext) {
    // Generate a random IV for AES-GCM (16 bytes)
    const iv = new Uint8Array(16)
    window.crypto.getRandomValues(iv)

    // Encrypt the plaintext using AES-256-GCM and the symmetric key
    // The result contains the AES-GCM authentication tag automatically appended at the end
    const encrypted = await window.crypto.subtle.encrypt(
        // Set the algorithm to AES-GCM and pass the IV
        {name: 'AES-GCM', iv: iv},
        // Symmetric key
        symmetricKey,
        // Message to encrypt
        plaintext
    )

    // Return the concatenation of the IV and the encrypted data (ciphertext)
    return new Uint8Array([
        ...iv,
        ...new Uint8Array(encrypted)
    ])
}

/**
 * Decrypts a message using the given key with AES-256-GCM
 * @param {CryptoKey} symmetricKey The 256-bit symmetric key that can be used to decrypt data with AES-GCM
 * @param {ArrayBufferLike} ciphertext A buffer containing the message to decrypt, which has the IV prepended and the AES-GCM authentication tag appended
 * @returns {Promise<ArrayBufferLike>} The decrypted message, as a buffer
 */
function symmetricDecrypt(symmetricKey, ciphertext) {
    // Extract the IV and the ciphertext from the ciphertext
    // The first 16 bytes are for the IV, the rest is for the ciphertext (which includes the authentication tag)
    const iv = ciphertext.slice(0, 16)
    const encrypted = ciphertext.slice(16)

    // Decrypt the message using AES-256-GCM and the symmetric key
    return window.crypto.subtle.decrypt(
        // Set the algorithm to AES-GCM and pass the IV
        {name: 'AES-GCM', iv: iv},
        // Symmetric key
        symmetricKey,
        // Ciphertext
        encrypted
    )
}

/**
 * Wrap a CryptoKey object (containing a symmetric key) using a public RSA key
 * @param {CryptoKey} publicKey Wrapping key: this is a RSA public key
 * @param {CryptoKey} key Symmetric key to wrap
 * @returns {Promise<ArrayBuffer>} Wrapped key
 */
function rsaKeyWrap(publicKey, key) {
    // Use the wrapKey method to export and wrap (encrypt) a key
    return window.crypto.subtle.wrapKey(
        // The symmetric key is in raw format
        'raw',
        // Key to wrap (the symmetric key)
        key,
        // Wrapping key (the public RSA key)
        publicKey,
        // Set the algorithm to RSA-OAEP
        {name: 'RSA-OAEP'}
    )
}

/**
 * Unwraps a symmetric key using a RSA private key.
 * The symmetric key will be in a CryptoKey object that can be used to decrypt data using AES-GCM.
 * @param {CryptoKey} privateKey Wrapping key: this is a RSA private key
 * @param {ArrayBufferLike} wrappedKey Wrapped symmetric key
 * @returns {Promise<CryptoKey>} Symmetric key object
 */
function rsaKeyUnwrap(privateKey, wrappedKey) {
    // Use the unwrapKey method to unwrap (decrypt) and import a key
    return window.crypto.subtle.unwrapKey(
        // The wrapped key is in raw format
        'raw',
        // Wrapped symmetric key
        wrappedKey,
        // Wrapping key (the private RSA key)
        privateKey,
        // Algorithm used to unwrap the key: RSA-OAEP
        {name: 'RSA-OAEP'},
        // The resulting CryptoKey object will be a symmetric key for usage with AES-GCM
        {name: 'AES-GCM'},
        // The resulting key is not extractable
        false,
        // The resulting key can be used to decrypt data only
        ['decrypt']
    )
}

/**
 * Generate a new RSA key pair, creating a new random key every time. The key can be used to wrap/unwrap other keys using RSA-OAEP.
 * Your application will need to retrieve the public and/or private keys in a way that is appropriate for it.
 *
 * @returns {Promise<CryptoKeyPair>} Key pair object
 */
function newRSAKeyPair() {
    // Generate a new 4096-bit key pair for encryption with RSA-OAEP
    return window.crypto.subtle.generateKey(
        // Options for the algorithm to use
        {
            // Name of the algorithm
            name: 'RSA-OAEP',
            // Length of the RSA key (modulus), in bits
            modulusLength: 4096,
            // Public exponent: always use this static value (equivalent to 65537)
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            // Hashing function to use, e.g. SHA-256, SHA-384, SHA-512 (or SHA-1)
            hash: 'SHA-256'
        },
        // Key is non-extractable
        false,
        // Key can be used for wrapping and unwrapping keys only
        ['wrapKey', 'unwrapKey']
    )
}
