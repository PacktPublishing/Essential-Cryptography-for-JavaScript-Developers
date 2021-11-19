const crypto = require('crypto')

// Promisify the randomBytes method
const randomBytes = require('util').promisify(crypto.randomBytes)

// Import the argon2 module
// https://www.npmjs.com/package/argon2
const argon2 = require('argon2')

/**
 * Type for the user's profile object
 * @typedef {Object} UserProfile
 * @property {Buffer} wrappedKey Wrapped user key
 * @property {Buffer} salt Salt (unique for the user) used to derive the wrapping key
 * @property {string} hash Hash of the user's passphrase, as a hex-encoded string
 */
/**
 * Our sample code doesn't use a database, so we keep all user data in an object here in memory.
 * Your app will store this to disk or in a database.
 * @type Record<string, UserProfile>
 */
const users = {}

// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async function() {
    // Create a new user with name 'alex' and passphrase 'passw0rd'
    // This returns three things that need to be stored in the user's profile:
    // - A random user key that is wrapped with a key derived from the user's passphrase (wrappedKey)
    // - A random salt that is used to derive the key from the user's passphrase, and it's unique for each user (salt)
    // - The hash of the user's passphrase, as a hex-encoded string
    // The user's data is then stored in the "database" - in this example, the `users` object in memory
    const newUser = await createUser('passw0rd')
    users['alex'] = newUser

    // When the user wants to encrypt or decrypt data, we need to retrieve the user key for the current user
    // We prompt the user for the passphrase again, and if it matches then we return the user key
    // The user key can then be used to encrypt or decrypt data
    // PS: Try setting a different passphrase!
    const userKey = await getUserKey(users['alex'], 'passw0rd')

    console.log({userKey})
})()

/**
 * Creates a new user, generating a random user key and wrapping it with a key derived from the user's passphrase and a random salt. It also returns the hash of the user's passphrase.
 * @param {string} passphrase User's passphrase
 * @returns {Promise<UserProfile>} The user's salt, the wrapped user key, and the hash of the user's passphrase
 */
async function createUser(passphrase) {
    // Calculate a new salt for this user which will be used to derive the wrapping key (UK) and hash the passphrase
    // Salts for Argon2 should be 16-byte long
    const salt = await randomBytes(16)

    // Derive the wrapping key from the user's passphrase as well as calculating the hash of the passphrase
    const derived = await deriveKeyHash(passphrase, salt)

    // Calculate a new 256-bit key as the user key, randomly
    const userKey = await randomBytes(32)

    // Wrap the user key with the wrapping key, using AES-KW (AES-256 in "wrap" mode)
    // Note that the IV is always 0xA6A6A6A6A6A6A6A6 as defined by RFC3394
    const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex')
    const cipher = crypto.createCipheriv('id-aes256-wrap', derived.wrappingKey, iv)
    const wrappedKey = Buffer.concat([
        cipher.update(userKey),
        cipher.final()
    ])

    // Return the user's salt, wrapped key, and the hash of the passphrase
    return {
        salt,
        wrappedKey,
        hash: derived.hash
    }
}

/**
 * Returns the user key (the encryption key for the user's data) by un-wrapping the one stored in the user's profile. This requires the user's passphrase. If the passphrase doesn't match the one that was submitted when the user was created, then an error is returned.
 * @param {UserProfile} profile User's profile object, containing the wrapped key, the salt, and the password hash
 * @param {string} passphrase User's passphrase
 * @returns {Promise<Buffer>} User key
 */
async function getUserKey(profile, passphrase) {
    // Start by deriving the wrapping key and passphrase hash
    // We are passing the salt that is stored in the user's profile
    const derived = await deriveKeyHash(passphrase, profile.salt)

    // Check if the hash of the passphrase matches the one in the user's profile
    if (derived.hash != profile.hash) {
        throw Error('The passphrase is not correct')
    }

    // Unwrap the user key using AES-KW (AES-256 in "wrap" mode), using the wrapping key
    // Note that the IV is always 0xA6A6A6A6A6A6A6A6 as defined by RFC3394
    const iv = Buffer.from('A6A6A6A6A6A6A6A6', 'hex')
    const decipher = crypto.createDecipheriv('id-aes256-wrap', derived.wrappingKey, iv)
    const userKey = Buffer.concat([
        decipher.update(profile.wrappedKey),
        decipher.final()
    ])

    // Return the user key
    return userKey
}

/**
 * Derive a 32-byte wrapping key (WK) from a given passphrase and salt, using Argon2 with explicit parameters. It also returns a 32-byte hash of the passphrase that is calculated with Argon2 too.
 * @param {string} passphrase User's passphrase
 * @param {Buffer} salt Salt used for this key; should be 16-byte long
 * @returns {Promise<{wrappingKey: Buffer, hash: string}>} The wrapping key derived with Argon2 (as a Buffer) and the passphrase hash (as a hex-encoded string).
 */
async function deriveKeyHash(passphrase, salt) {
    try {
        // Parameters for argon2
        const params = {
            // Set to return the raw bytes and not a base64-encoded hash
            raw: true,
            // We are requesting 64 bytes: 32 for the key and 32 for the password hash
            hashLength: 64,
            // Pass the salt
            salt: salt,
            // We need to make them all parameters explicit just in case the default ones in the library changed.
            // In fact, if that happened, the same passphrase and salt would return a different key and we wouldn't be able to decrypt our data encrypted with that key and salt combination.
            // You can tweak these as needed.
            type: argon2.argon2id,
            timeCost: 3,
            memoryCost: 4096,
            parallelism: 1,
            version: 0x13,
        }

        // Run the KDF and return the result
        const result = await argon2.hash(passphrase, params)
        return {
            // The first 32 bytes are the wrapping key
            // We return those as a Buffer
            wrappingKey: result.slice(0, 32),
            // The remaining 32 bytes are the hash of the passphrase
            // We return those as a hex-encoded string
            hash: result.slice(32).toString('hex')
        }
    }
    catch (err) {
        console.error('An internal error occurred: ', err)
    }
}
