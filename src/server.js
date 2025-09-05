import express from "express";
import cors from "cors"; // ✅ new
import { PrismaClient } from "@prisma/client";
import { Block, certificateChain, hashData } from "./blockchain.js";
import multer from "multer";
import csv from "csv-parser";
import fs from "fs";
import path from "path";

const prisma = new PrismaClient();
const app = express();
app.use(express.json());

// ✅ Allow frontend (Next.js) to talk to backend
app.use(cors({
  origin: "http://localhost:3001", // your Next.js dev server
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"],
}));

// Multer for file upload
const upload = multer({ dest: "uploads/" });

/**
 * Generate unique certificate ID like Trust2001
 */
async function generateCertificateId() {
  const count = await prisma.certificate.count();
  return `Trust${2000 + count + 1}`;
}

/**
 * Health check
 */
app.get("/", (req, res) => {
  res.send("✅ Server is working");
});

/**
 * Upload CSV and insert records
 * CSV headers: studentName,email,dob,course,adharNumber
 */
app.post("/upload-csv", upload.single("file"), async (req, res) => {
  const filePath = path.join(process.cwd(), req.file.path);
  const results = [];

  fs.createReadStream(filePath)
    .pipe(csv())
    .on("data", (row) => results.push(row))
    .on("end", async () => {
      fs.unlinkSync(filePath); // cleanup temp file

      const inserted = [];

      for (const row of results) {
        try {
          const { studentName, email, dob, course, adharNumber } = row;

          if (!studentName || !email || !dob || !course || !adharNumber) {
            continue; // skip invalid rows
          }

          const certificateId = await generateCertificateId();
          const adharHash = hashData(adharNumber);

          const blockchainHash = certificateChain.addBlock(
            new Block(certificateChain.chain.length, Date.now().toString(), {
              certificateId,
              studentName,
              email,
              dob: new Date(dob).toISOString(),
              course,
              adharHash,
            })
          );

          const cert = await prisma.certificate.create({
            data: {
              certificateId,
              studentName,
              email,
              dob: new Date(dob),
              course,
              adharHash,
              blockchainHash,
            },
          });

          inserted.push(cert);
        } catch (err) {
          console.error("❌ Error inserting row:", row, err);
        }
      }

      res.json({ message: "✅ CSV processed", inserted });
    })
    .on("error", (err) => {
      console.error(err);
      res.status(500).json({ error: "❌ Error processing CSV file" });
    });
});

/**
 * Issue a single certificate (manual)
 */
app.post("/issue", async (req, res) => {
  try {
    const { studentName, email, dob, course, adharNumber } = req.body;

    if (!studentName || !email || !dob || !course || !adharNumber) {
      return res.status(400).json({ error: "⚠️ All fields are required" });
    }

    const certificateId = await generateCertificateId();
    const adharHash = hashData(adharNumber);

    const blockchainHash = certificateChain.addBlock(
      new Block(certificateChain.chain.length, Date.now().toString(), {
        certificateId,
        studentName,
        email,
        dob: new Date(dob).toISOString(),
        course,
        adharHash,
      })
    );

    const cert = await prisma.certificate.create({
      data: {
        certificateId,
        studentName,
        email,
        dob: new Date(dob),
        course,
        adharHash,
        blockchainHash,
      },
    });

    res.json({ message: "✅ Certificate Issued", cert });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "❌ Error issuing certificate" });
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

    if (!cert) return res.status(404).json({ error: "⚠️ Certificate not found" });

    res.json(cert);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "❌ Error fetching certificate" });
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

    if (!cert) return res.status(404).json({ error: "⚠️ Certificate not found" });

    // Reconstruct hash from current DB data
    const currentString = `${cert.certificateId}|${cert.studentName}|${cert.email}|${cert.dob.toISOString()}|${cert.course}|${cert.adharHash}`;
    const currentHash = hashData(currentString);

    // Get the original block from blockchain
    const block = certificateChain.findBlockByHash(cert.blockchainHash);

    if (!block) {
      return res.json({
        valid: false,
        reason: "⚠️ Block not found in blockchain",
        cert,
      });
    }

    // Reconstruct original hash from blockchain data
    const blockchainString = `${block.data.certificateId}|${block.data.studentName}|${block.data.email}|${new Date(block.data.dob).toISOString()}|${block.data.course}|${block.data.adharHash}`;
    const blockchainHash = hashData(blockchainString);

    if (currentHash === blockchainHash && certificateChain.isValid()) {
      res.json({
        valid: true,
        message: "✅ Certificate is authentic and untampered",
        cert,
      });
    } else {
      res.json({
        valid: false,
        reason: "❌ Data tampered! DB does not match blockchain",
        cert,
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "❌ Error verifying certificate" });
  }
});

app.listen(3000, () => {
  console.log("🚀 Server running at http://localhost:3000");
});
