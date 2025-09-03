// secure-blockchain-no-jwt-check-api.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const CryptoJS = require('crypto-js');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
app.use(bodyParser.json());
app.use(helmet());
app.use(cors());

// ------------------ SECURITY SETTINGS ------------------
const API_SECRET = process.env.API_SECRET || "super-secret-key-123";
const HASHED_KEY = bcrypt.hashSync(API_SECRET, 10);
let lastMineTime = 0;
const MINING_COOLDOWN_MS = 5000; // 5 seconds cooldown

// ------------------ RATE LIMIT ------------------
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: "Too many requests, try again later." }
});
app.use(limiter);

// ------------------ Utility: Double SHA-256 ------------------
function doubleSHA256(input) {
  return CryptoJS.SHA256(CryptoJS.SHA256(input)).toString();
}

// ------------------ Merkle Root ------------------
function merkleRoot(transactions) {
  if (!transactions.length) return '';
  let hashes = transactions.map(tx => doubleSHA256(JSON.stringify(tx)));
  while (hashes.length > 1) {
    if (hashes.length % 2 !== 0) hashes.push(hashes[hashes.length - 1]);
    const next = [];
    for (let i = 0; i < hashes.length; i += 2) {
      next.push(doubleSHA256(hashes[i] + hashes[i + 1]));
    }
    hashes = next;
  }
  return hashes[0];
}

// ------------------ BLOCK CLASS ------------------
class Block {
  constructor(index, transactions, previousHash = '') {
    this.index = index;
    this.timestamp = Date.now();
    this.transactions = transactions;
    this.previousHash = previousHash;
    this.merkleRoot = merkleRoot(transactions);
    this.nonce = 0;
    this.hash = this.calculateHash();
  }

  calculateHash() {
    return doubleSHA256(
      this.index +
      this.previousHash +
      this.timestamp +
      this.merkleRoot +
      this.nonce
    );
  }

  mineBlock(difficulty) {
    const target = Array(difficulty + 1).join("0");
    while (this.hash.substring(0, difficulty) !== target) {
      this.nonce++;
      this.hash = this.calculateHash();
    }
    console.log(`✅ Block mined: ${this.hash}`);
  }
}

// ------------------ BLOCKCHAIN CLASS ------------------
class Blockchain {
  constructor() {
    this.chain = [this.createGenesisBlock()];
    this.difficulty = 4;
  }

  createGenesisBlock() {
    return new Block(0, [{ message: "Genesis Block" }], "0");
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  addBlock(transactions) {
    const newBlock = new Block(
      this.chain.length,
      transactions,
      this.getLatestBlock().hash
    );
    newBlock.mineBlock(this.difficulty);
    this.chain.push(newBlock);
  }

  isChainValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const current = this.chain[i];
      const previous = this.chain[i - 1];
      if (current.hash !== current.calculateHash()) return false;
      if (current.previousHash !== previous.hash) return false;
      if (current.merkleRoot !== merkleRoot(current.transactions)) return false;
    }
    return true;
  }
}

const myChain = new Blockchain();

// ------------------ AUTH MIDDLEWARE ------------------
function authenticate(req, res, next) {
  const key = req.headers['x-api-key'];
  if (!key || !bcrypt.compareSync(key, HASHED_KEY)) {
    return res.status(403).json({ error: "Forbidden: Invalid API Key" });
  }
  next();
}

// ------------------ ROUTES ------------------

// Get entire blockchain
app.get('/chain', authenticate, (req, res) => {
  res.json(myChain);
});

// Mine a new block
app.post('/mine', authenticate, (req, res) => {
  const { data } = req.body;
  if (!data) return res.status(400).json({ error: "No data provided" });

  const now = Date.now();
  if (now - lastMineTime < MINING_COOLDOWN_MS) {
    return res.status(429).json({ error: "Rate limit: Please wait before mining again." });
  }
  lastMineTime = now;

  myChain.addBlock([data]);
  res.json({ message: "Block mined successfully!", chain: myChain });
});

// Validate the blockchain
app.get('/validate', authenticate, (req, res) => {
  res.json({ valid: myChain.isChainValid() });
});

// ------------------ START SERVER ------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🔒 Secure blockchain running at http://localhost:${PORT}`);
});
