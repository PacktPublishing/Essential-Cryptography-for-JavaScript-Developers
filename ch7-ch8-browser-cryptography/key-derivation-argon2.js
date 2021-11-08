// Argon2 for the browser is available in the argon2-browser module from NPM
// The package also exports "argon2i" and "argon2d" for other Argon2 variants
import {argon2id} from 'hash-wasm'

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Passphrase to derive the key from
    const passphrase = 'correct horse battery staple'

    // Generate a random, 16-byte salt
    const salt = new Uint8Array(16)
    window.crypto.getRandomValues(salt)

    // Derive a 32-byte key from a passphrase using argon2id (with the method imported from the hash-wasm NPM module)
    const rawKey = await argon2id({
        password: passphrase,
        salt: salt,

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

    // Import the calculated hash as an AES-256 symmetric key
    const key = await window.crypto.subtle.importKey(
        // Specify that the key is in raw format, i.e. just a byte sequence
        'raw',
        // The key's bytes
        rawKey,
        // Because the key will be used for AES-GCM, specify that as algorithm
        'AES-GCM',
        // Make the key not extractable
        false,
        // Specify allowed uses of the key, for example:
        ['encrypt', 'decrypt']
    )

    // Use the key
    console.log(key)
})()
