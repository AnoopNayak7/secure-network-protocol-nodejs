const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

// Generate RSA Key Pair (Public and Private Keys)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
});

// Endpoint to get the server's public key
app.get('/public-key', (req, res) => {
    res.json({ publicKey: publicKey.export({ type: 'pkcs1', format: 'pem' }) });
});

// Endpoint to receive the encrypted symmetric key
let symmetricKey;
app.post('/receive-key', (req, res) => {
    const { encryptedSymmetricKey } = req.body;

    // Decrypt the symmetric key using the server's private key
    symmetricKey = crypto.privateDecrypt(
        { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
        Buffer.from(encryptedSymmetricKey, 'base64')
    );

    res.json({ message: 'Symmetric key received successfully.' });
});

// Endpoint to decrypt a message using the symmetric key
app.post('/decrypt', (req, res) => {
    if (!symmetricKey) {
        return res.status(400).json({ error: 'No symmetric key provided yet.' });
    }

    const { encryptedMessage } = req.body;
    
    const decipher = crypto.createDecipheriv('aes-256-cbc', symmetricKey, Buffer.alloc(16, 0)); // IV is 16 null bytes for simplicity
    let decrypted = decipher.update(encryptedMessage, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    res.json({ decryptedMessage: decrypted });
});

app.listen(3000, () => {
    console.log('Secure server listening on http://localhost:3000');
});
