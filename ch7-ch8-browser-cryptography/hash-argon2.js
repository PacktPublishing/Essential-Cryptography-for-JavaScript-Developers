// Argon2 for the browser is available in the argon2-browser module from NPM
// The package also exports "argon2i" and "argon2d" for other Argon2 variants
import {argon2id, argon2Verify} from 'hash-wasm'

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Passphrase to hash
    const passphrase = 'correct horse battery staple'

    // Generate a random, 16-byte salt
    const salt = new Uint8Array(16)
    window.crypto.getRandomValues(salt)

    // Hash a passphrase using argon2id (with the method imported from the hash-wasm NPM module)
    const hash = await argon2id({
        password: passphrase,
        salt: salt,

        // Length of the output in bytes
        // We are requesting a 32-byte (256-bit) hash
        hashLength: 32,

        // Return type
        // Because we're hashing a passphrase, we want the "encoded" format that includes all parameters needed to verify the hash in the output
        outputType: 'encoded',

        // Parameters for deriving the key
        // These are the default values that node-argon2 uses and may need tuning depending on your requirements
        // Information on parameter choice can be found in RFC-9106, section 4:
        // https://datatracker.ietf.org/doc/html/rfc9106#section-4
        parallelism: 1,
        iterations: 3,
        memorySize: 4096, // In KB
    })
    console.log('Hash:', hash)

    // Verify the passphrase against the hash
    const isValid = await argon2Verify({
        password: passphrase,
        hash: hash
    })
    console.log('Is valid?', isValid)
})()

/*
Example result (will be different every time):
  Hash: $argon2id$v=19$m=4096,t=3,p=1$iSuXUkWhJ9343KE0W9BEgA$dL83TLLTij9wLnfJXCTnF0IAMPvgXR3VSIefINM78vs
  Is valid? true
*/
