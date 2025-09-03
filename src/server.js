import express from "express";
import { PrismaClient } from "@prisma/client";
import { Block, certificateChain, hashData } from "./blockchain.js";

const prisma = new PrismaClient();
const app = express();
app.use(express.json());

/**
 * Generate unique certificate ID like Trust2001
 */
async function generateCertificateId() {
  const count = await prisma.certificate.count();
  return `Trust${2000 + count + 1}`;
}

/**
 * Issue a new certificate
 */
app.get("/",(req,res)=>{
    res.send("working")
})

app.post("/issue", async (req, res) => {
  try {
    const { studentName, email, dob, course, adharNumber } = req.body;

    if (!studentName || !email || !dob || !course || !adharNumber) {
      return res.status(400).json({ error: "All fields are required" });
    }

    const certificateId = await generateCertificateId();
    const adharHash = hashData(adharNumber);

    // Normalize date format before hashing
    const uniqueString = `${certificateId}|${studentName}|${email}|${new Date(dob).toISOString()}|${course}|${adharHash}`;

    const blockchainHash = certificateChain.addBlock(
      new Block(
        certificateChain.chain.length,
        Date.now().toString(),
        {
          certificateId,
          studentName,
          email,
          dob: new Date(dob).toISOString(),
          course,
          adharHash
        }
      )
    );

    const cert = await prisma.certificate.create({
      data: {
        certificateId,
        studentName,
        email,
        dob: new Date(dob),
        course,
        adharHash,
        blockchainHash
      },
    });

    res.json({ message: "Certificate Issued", cert });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error issuing certificate" });
  }
});

/**
 * Get all certificates
 */
app.get("/certificates", async (req, res) => {
  const certs = await prisma.certificate.findMany();
  res.json(certs);
});

/**
 * Get certificate by ID
 */
app.get("/certificate/:certificateId", async (req, res) => {
  try {
    const cert = await prisma.certificate.findUnique({
      where: { certificateId: req.params.certificateId },
    });

    if (!cert) return res.status(404).json({ error: "Certificate not found" });

    res.json(cert);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error fetching certificate" });
  }
});

/**
 * Verify certificate integrity
 */
app.get("/verify/:certificateId", async (req, res) => {
  try {
    const cert = await prisma.certificate.findUnique({
      where: { certificateId: req.params.certificateId },
    });

    if (!cert) return res.status(404).json({ error: "Certificate not found" });

    // Reconstruct hash from current DB data
    const currentString = `${cert.certificateId}|${cert.studentName}|${cert.email}|${cert.dob.toISOString()}|${cert.course}|${cert.adharHash}`;
    const currentHash = hashData(currentString);

    // Get the original block from blockchain
    const block = certificateChain.findBlockByHash(cert.blockchainHash);

    if (!block) {
      return res.json({
        valid: false,
        reason: "Block not found in blockchain",
        cert,
      });
    }

    // Reconstruct original hash from blockchain data
    const blockchainString = `${block.data.certificateId}|${block.data.studentName}|${block.data.email}|${new Date(block.data.dob).toISOString()}|${block.data.course}|${block.data.adharHash}`;
    const blockchainHash = hashData(blockchainString);

    if (currentHash === blockchainHash && certificateChain.isValid()) {
      res.json({
        valid: true,
        message: "Certificate is authentic and untampered",
        cert,
      });
    } else {
      res.json({
        valid: false,
        reason: "Data tampered! Current DB data does not match blockchain record",
        cert,
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Error verifying certificate" });
  }
});

app.listen(3000, () => {
  console.log("🚀 Server running at http://localhost:3000");
});
