// This depends on a base64 encoding library, such as arraybuffer-encoding from NPM
import {Encode} from 'arraybuffer-encoding/base64/standard'

/**
 * Exports a public or private key from a CryptoKey object, returning it in a PEM-encoded string.
 * Supports keys in PKCS#8 and SPKI formats, for private and public keys respectively.
 * @param keyType {'public'|'private'} Type of the key: public or private
 * @param key {CryptoKey} Key to export
 * @returns {Promise<string>} The exported key, PEM-encoded
 */
async function pemFromKey(keyType, key) {
    // Get the key format and the header and footer depending on the key type
    let format, header, footer
    switch (keyType) {
        case 'public':
            format = 'spki'
            header = '-----BEGIN PUBLIC KEY-----'
            footer = '-----END PUBLIC KEY-----'
            break
        case 'private':
            format = 'pkcs8'
            header = '-----BEGIN PRIVATE KEY-----'
            footer = '-----END PRIVATE KEY-----'
            break
        default:
            throw Error('Invalid key type')
    }

    // Export the key, DER-encoded, in an ArrayBuffer object
    const keyData = await window.crypto.subtle.exportKey(format, key)
    // Merge the header, the base64-encoded key, and the footer, separated by newlines
    const pem = [
        header,
        // This encodes the key as base64, and then uses a one-liner trick to add a newline every 64 characters
        Encode(keyData).replace(/(.{64})/g, '$1\n'),
        footer
    ].join('\n')
    // Return the PEM-encoded string
    return pem
}

/* Example usage */

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Generate a new RSA key pair (for digital signatures with RSA-PSS)
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: 'RSA-PSS',
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256'
        },
        true,
        ['sign', 'verify']
    )

    // Export the public and private parts as PEM strings
    const publicKey = await pemFromKey('public', keyPair.publicKey)
    const privateKey = await pemFromKey('private', keyPair.privateKey)

    // Print the result
    console.log(publicKey)
    console.log(privateKey)
})()
