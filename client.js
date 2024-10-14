const axios = require('axios');
const crypto = require('crypto');

// Step 1: Get the server's public key
async function getPublicKey() {
    const response = await axios.get('http://localhost:3000/public-key');
    return response.data.publicKey;
}

// Step 2: Generate a symmetric key (AES-256)
const symmetricKey = crypto.randomBytes(32);  // 256-bit key

// Step 3: Encrypt and send the symmetric key to the server
async function sendSymmetricKey(publicKeyPem) {
    const publicKey = crypto.createPublicKey(publicKeyPem);

    // Encrypt the symmetric key using the server's public key
    const encryptedSymmetricKey = crypto.publicEncrypt(
        { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
        symmetricKey
    );

    await axios.post('http://localhost:3000/receive-key', {
        encryptedSymmetricKey: encryptedSymmetricKey.toString('base64'),
    });

    console.log('Symmetric key sent to the server.');
}

// Step 4: Encrypt a message using the symmetric key
function encryptMessage(message) {
    const cipher = crypto.createCipheriv('aes-256-cbc', symmetricKey, Buffer.alloc(16, 0)); // IV is 16 null bytes
    let encrypted = cipher.update(message, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return encrypted;
}

// Step 5: Send the encrypted message to the server
async function sendEncryptedMessage(message) {
    const encryptedMessage = encryptMessage(message);
    const response = await axios.post('http://localhost:3000/decrypt', { encryptedMessage });
    console.log('Decrypted message from server:', response.data.decryptedMessage);
}

(async () => {
    const publicKey = await getPublicKey();
    await sendSymmetricKey(publicKey);

    const message = "This is a secure message!";
    await sendEncryptedMessage(message);
})();
