// Wrap in an asynchronous IIFE (Immediately-Invoked Function Expression) because we need to use the await keyword
;(async () => {
    // Message to encrypt
    const plaintextMessage = 'Hello world!'

    // Generate a random 256-bit key for use with AES-CBC
    const key = await window.crypto.subtle.generateKey(
        // Algorithm the key will be used for and size
        {name: 'AES-CBC', length: 256},
        // Key is non-extractable
        false,
        // Key can be used for encryption/decryption only
        ['encrypt', 'decrypt']
    )

    // Convert the plaintext message to a buffer (Uint8Array)
    const encoder = new TextEncoder()
    const plaintext = encoder.encode(plaintextMessage)

    // Generate a random IV for AES-CBC (16 bytes)
    let iv = new Uint8Array(16)
    window.crypto.getRandomValues(iv)

    // Encrypt the plaintext using AES-256-CBC
    let encrypted = await window.crypto.subtle.encrypt(
        // Set the algorithm to AES-CBC and pass the IV
        {name: 'AES-CBC', iv: iv},
        // Key object
        key,
        // Plaintext message as buffer
        plaintext
    )

    // Concatenate the IV and the encrypted data (ciphertext)
    // This is the data that should be stored or transmitted
    const encryptedStore = new Uint8Array([
        ...iv,
        ...new Uint8Array(encrypted)
    ])
    console.log('encryptedStore:', encryptedStore)

    // Extract the IV and the ciphertext from encryptedStore
    // The first 16 bytes are for the IV, the rest is for the ciphertext
    // We're overwriting the iv and encrypted variables with values that are the same as they were before, but this is just for an example on how to revert the concatenation!
    iv = encryptedStore.slice(0, 16)
    encrypted = encryptedStore.slice(16)

    // Decrypt the ciphertext using AES-256-CBC and the same key
    const decrypted = await window.crypto.subtle.decrypt(
        // Set the algorithm to AES-CBC and pass the IV
        {name: 'AES-CBC', iv: iv},
        // Key object
        key,
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
Example result (truncated):
  encryptedStore: Uint8Array(32) [...]
  decrypted: Hello world!
*/
