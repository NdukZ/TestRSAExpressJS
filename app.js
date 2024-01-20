const express = require('express');
const bodyParser = require('body-parser');
const BigInteger = require('big-integer');

const app = express();
const port = 3000;

// Fungsi untuk enkripsi
function encrypt(message, publicKey, n) {
  return message.modPow(publicKey, n);
}

// Fungsi untuk dekripsi
function decrypt(ciphertext, privateKey, n) {
  return ciphertext.modPow(privateKey, n);
}

app.use(bodyParser.json());

app.post('/generateKeys', (req, res) => {
  const p = BigInteger(req.body.p);
  const q = BigInteger(req.body.q);

  const n = p.multiply(q); // Hitung n
  const phi = p.subtract(1).multiply(q.subtract(1)); // Hitung phi(n)

  // Pilih eksponen e (biasanya dipilih 65537)
  const e = BigInteger('65537');

  // Hitung d (private key)
  const d = e.modInv(phi);

  // Public Key
  const publicKey = { e, n };

  // Private Key
  const privateKey = { d, n };

  // return { publicKey, privateKey };
  res.json({ publicKey, privateKey });
});

app.post('/encrypt', (req, res) => {
  const message = BigInteger(req.body.message);
  const publicKey = BigInteger(req.body.publicKey.e);
  const n = BigInteger(req.body.publicKey.n);

  const ciphertext = encrypt(message, publicKey, n);
  res.json({ ciphertext: ciphertext.toString() });
});

app.post('/decrypt', (req, res) => {
  const ciphertext = BigInteger(req.body.ciphertext);
  const privateKey = BigInteger(req.body.privateKey.d);
  const n = BigInteger(req.body.privateKey.n);

  const decryptedMessage = decrypt(ciphertext, privateKey, n);
  res.json({ decryptedMessage: decryptedMessage.toString() });
});

app.listen(port, () => {
  console.log("Server is running");
});