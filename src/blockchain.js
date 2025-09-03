import crypto from "crypto";
import dotenv from "dotenv";
dotenv.config();

// Secret key from environment
const SECRET_KEY = process.env.SECRET_KEY || "DefaultKey";

/**
 * Hash data using SHA-256 with HMAC and secret key
 */
export const hashData = (data) => {
  return crypto
    .createHmac("sha256", SECRET_KEY)
    .update(String(data))
    .digest("hex");
};

/**
 * Block structure
 */
export class Block {
  constructor(index, timestamp, data, prevHash = "") {
    this.index = index;
    this.timestamp = timestamp;
    this.data = data;
    this.prevHash = prevHash;
    this.hash = this.calculateHash();
  }

  calculateHash() {
    return crypto
      .createHmac("sha256", SECRET_KEY)
      .update(
        this.index +
          this.timestamp +
          JSON.stringify(this.data) +
          this.prevHash
      )
      .digest("hex");
  }
}

/**
 * Blockchain class
 */
class Blockchain {
  constructor() {
    this.chain = [this.createGenesisBlock()];
  }

  createGenesisBlock() {
    return new Block(0, Date.now().toString(), "Genesis Block", "0");
  }

  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  addBlock(newBlock) {
    newBlock.prevHash = this.getLatestBlock().hash;
    newBlock.hash = newBlock.calculateHash();
    this.chain.push(newBlock);
    return newBlock.hash;
  }

  isValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const current = this.chain[i];
      const previous = this.chain[i - 1];

      if (current.hash !== current.calculateHash()) return false;
      if (current.prevHash !== previous.hash) return false;
    }
    return true;
  }

  findBlockByHash(hash) {
    return this.chain.find((block) => block.hash === hash) || null;
  }
}

export const certificateChain = new Blockchain();
