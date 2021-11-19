// This depends on a hex encoding library, such as arraybuffer-encoding from NPM
import {Encode, Decode} from 'arraybuffer-encoding/base64/standard'

// Argon2 for the browser is available in the argon2-browser module from NPM
// The package also exports "argon2i" and "argon2d" for other Argon2 variants
import {argon2id} from 'hash-wasm'

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Passphrase to derive the key from, using Argon2id
    const passphrase = 'correct horse battery staple'

    // Salt used to derive the key from the passphrase (for Argon2id)
    // This is normally generated per-user and stored with the user's profile in your application's data
    // The salt doesn't need to be secret
    // In this example, the salt is base64-encoded and needs to be decoded
    const salt = Decode('0tZSVPntDHSRiLlD4tYOjA==')

    // Generate a new symmetric key (for example, for AES-CBC) key that will be later wrapped
    const symmetricKey = await window.crypto.subtle.generateKey(
        // Algorithm the key will be used for and size
        {name: 'AES-CBC', length: 256},
        // Key needs to be extractable because we are exporting it when it's wrapped
        true,
        // Set key usages as appropriate for your app
        ['encrypt', 'decrypt']
    )

    // We then need a wrapping key, which will be used to wrap (encrypt) the key object just generated
    // In this case, we're deriving the key from the passphrase (and salt) using Argon2id
    // The result is a CryptoKey object that can be used to wrap/unwrap keys using AES-KW
    const wrappingKey = await deriveKey(passphrase, salt)

    // Wrap the symmetric key using the wrapping key and AES-KW
    const wrappedKey = await window.crypto.subtle.wrapKey(
        // Symmetric keys are in "raw" format
        'raw',
        // Key to wrap
        symmetricKey,
        // Wrapping key
        wrappingKey,
        // Use AES-KW to wrap the key
        {name: 'AES-KW'}
    )
    console.log({
        wrappedKey: Encode(wrappedKey)
    })

    // Perform the opposite operation, and unwrap the wrapped key using AES-KW and the same wrapping key
    // The result should be a key that is identical to symmetricKey (but it's a separate object)
    const unwrappedKey = await window.crypto.subtle.unwrapKey(
        // The wrapped key is in raw format
        'raw',
        // Wrapped symmetric key
        wrappedKey,
        // Wrapping key
        wrappingKey,
        // Algorithm used to unwrap the key: AES-KW
        {name: 'AES-KW'},
        // The resulting CryptoKey object will be a symmetric key for usage with AES-CBC
        {name: 'AES-CBC'},
        // The resulting key is not extractable
        false,
        // The resulting key can be used to encrypt and decrypt data (for example)
        ['encrypt', 'decrypt']
    )
    console.log({
        unwrappedKey: unwrappedKey
    })
})()

/*
Example result (will be different every time):
  {wrappedKey: 'LpZAN7NSm7pbgnywV5ez8SLRY07jAsvscgImuXSHSkQeJH+XHjMOaw=='}
  {
    unwrappedKey:  CryptoKey {
      algorithm: {name: 'AES-CBC', length: 256}
      extractable: false
      type: "secret"
      usages: (2) ['encrypt', 'decrypt']
    }
  }
*/

/**
 * Derive a symmetric key from a passphrase using Argon2id.
 * The resulting key can be used to wrap and unwrap keys using AES-KW.
 * @param {string} passphrase Passphrase used to derive the key from
 * @param {ArrayBufferLike} salt Salt used to derive the key
 * @returns {Promise<CryptoKey>} Object containing the symmetric key derived from the passphrase
 */
async function deriveKey(passphrase, salt) {
    // Derive a 32-byte key from a passphrase using argon2id (with the method imported from the hash-wasm NPM module)
    const rawKey = await argon2id({
        password: passphrase,
        // Ensure that if salt is an ArrayBuffer, it's now in a Uint8Array object
        salt: new Uint8Array(salt),

        // Length of the output in bytes
        // We are requesting a 32-byte (256-bit) key
        hashLength: 32,

        // Return type
        // Because we're deriving a key, we want the function to return a Uint8Array
        outputType: 'binary',

        // Parameters for deriving the key
        // These are the default values that node-argon2 uses and may need tuning depending on your requirements
        // Information on parameter choice can be found in RFC-9106, section 4:
        // https://datatracker.ietf.org/doc/html/rfc9106#section-4
        parallelism: 1,
        iterations: 3,
        memorySize: 4096, // In KB
    })

    // Import the calculated hash as an AES-256 symmetric key that can be used for AES-KW
    return window.crypto.subtle.importKey(
        // Specify that the key is in raw format, i.e. just a byte sequence
        'raw',
        // The key's bytes
        rawKey,
        // This key will be used for AES-KW
        'AES-KW',
        // Make the key not extractable
        false,
        // This key can be used to wrap and unwrap other keys only
        ['wrapKey', 'unwrapKey']
    )
}
