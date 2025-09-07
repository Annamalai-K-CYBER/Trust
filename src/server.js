import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";
import { Block, certificateChain, hashData } from "./blockchain.js";
import multer from "multer";
import csv from "csv-parser";
import fs from "fs";
import path from "path";
import crypto from "crypto";

const prisma = new PrismaClient();
const app = express();
app.use(express.json());

// ------------------ AES-256 Encryption ------------------
const SECRET_KEY = process.env.ENCRYPTION_KEY
  ? Buffer.from(process.env.ENCRYPTION_KEY, "hex")
  : crypto.randomBytes(32); // fallback for dev
const IV_LENGTH = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-cbc", SECRET_KEY, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function decrypt(encryptedText) {
  if (!encryptedText) return null;
  const parts = encryptedText.split(":");
  if (parts.length !== 2) return null;
  const [ivHex, encrypted] = parts;
  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-cbc", SECRET_KEY, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}
// --------------------------------------------------------

// ✅ Date parser
function parseDate(dobStr) {
  const date = new Date(dobStr);
  if (isNaN(date)) {
    throw new Error(`Invalid DOB format: ${dobStr}`);
  }
  return date;
}

// Allow frontend dev servers
app.use(
  cors({
    origin: ["http://localhost:3000", "http://localhost:3001"],
    credentials: true,
  })
);

// File uploads
const upload = multer({ dest: "uploads/" });

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_key";

// ------------------ Middleware ------------------
function authMiddleware(role) {
  return async (req, res, next) => {
    try {
      const token = req.headers.authorization?.split(" ")[1];
      if (!token) return res.status(401).json({ error: "No token provided" });

      const decoded = jwt.verify(token, JWT_SECRET);
      if (role && decoded.role !== role)
        return res.status(403).json({ error: "Forbidden" });

      req.user = decoded;
      next();
    } catch (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ error: "Token expired" });
      }
      console.error("Auth error:", err);
      return res.status(401).json({ error: "Invalid token" });
    }
  };
}

// ------------------ Routes ------------------

// Admin login
app.post("/admin/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const admin = await prisma.admin.findUnique({ where: { email } });
    if (!admin) return res.status(404).json({ error: "Admin not found" });

    const match = await bcrypt.compare(password, admin.password);
    if (!match) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign(
      { id: admin.id, email: admin.email, role: "admin" },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Admin: List colleges
app.get("/admin/colleges", authMiddleware("admin"), async (req, res) => {
  try {
    const colleges = await prisma.college.findMany();
    res.json(colleges);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// Admin: Add college
app.post("/admin/add-college", authMiddleware("admin"), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: "All fields required" });

    const hashed = await bcrypt.hash(password, 10);
    const college = await prisma.college.create({
      data: { name, email, password: hashed },
    });

    res.json({ message: "College added", college });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Error adding college" });
  }
});

// ------------------ College: Course Summary ------------------
app.get(
  "/college/course-summary",
  authMiddleware("college"),
  async (req, res) => {
    try {
      const certs = await prisma.certificate.findMany({
        where: { collegeId: req.user.id },
      });

      const summary = certs.reduce((acc, c) => {
        const course = decrypt(c.course);
        if (course && course.trim() !== "") {
          acc[course] = (acc[course] || 0) + 1;
        }
        return acc;
      }, {});

      const result = Object.entries(summary).map(([course, count]) => ({
        course,
        count,
      }));

      res.json(result);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to get course summary" });
    }
  }
);

// ------------------ College: Update Certificate ------------------
app.put(
  "/college/update-certificate/:certificateId",
  authMiddleware("college"),
  async (req, res) => {
    try {
      const { certificateId } = req.params;
      const { studentName, email, course, dob, rollNo } = req.body;

      const cert = await prisma.certificate.findUnique({
        where: { certificateId },
      });
      if (!cert)
        return res.status(404).json({ error: "Certificate not found" });

      const updatedBlockHash = certificateChain.addBlock(
        new Block(certificateChain.chain.length, Date.now().toString(), {
          certificateId,
          studentName: studentName || decrypt(cert.studentName),
          email: email || decrypt(cert.email),
          dob: dob ? parseDate(dob).toISOString() : cert.dob.toISOString(),
          course: course || decrypt(cert.course),
          adharHash: cert.adharHash,
          rollNo: rollNo || cert.rollNo,
          college: req.user.name,
        })
      );

      const updatedCert = await prisma.certificate.update({
        where: { certificateId },
        data: {
          studentName: studentName ? encrypt(studentName) : cert.studentName,
          email: email ? encrypt(email) : cert.email,
          course: course ? encrypt(course) : cert.course,
          dob: dob ? parseDate(dob) : cert.dob,
          rollNo: rollNo || cert.rollNo,
          blockchainHash: updatedBlockHash,
        },
      });

      res.json({ message: "Certificate updated", updatedCert });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to update certificate" });
    }
  }
);

// College login
app.post("/college/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const college = await prisma.college.findUnique({ where: { email } });
    if (!college) return res.status(404).json({ error: "College not found" });

    const match = await bcrypt.compare(password, college.password);
    if (!match) return res.status(401).json({ error: "Invalid password" });

    const token = jwt.sign(
      { id: college.id, name: college.name, role: "college" },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({ token, name: college.name });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// College: Get certificates
app.get(
  "/college/my-certificates",
  authMiddleware("college"),
  async (req, res) => {
    try {
      const certs = await prisma.certificate.findMany({
        where: { collegeId: req.user.id },
        include: { college: true },
        orderBy: { createdAt: "desc" },
      });

      const decrypted = certs.map((c) => ({
        ...c,
        studentName: decrypt(c.studentName),
        email: decrypt(c.email),
        course: decrypt(c.course),
        adharNumber: c.adharEncrypted ? decrypt(c.adharEncrypted) : null,
        rollNo: c.rollNo,
        collegeName: c.college?.name || null,
      }));

      res.json(decrypted);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
    }
  }
);

// ------------------ College: Upload CSV ------------------
app.post(
  "/college/upload-csv",
  authMiddleware("college"),
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) return res.status(400).json({ error: "No file uploaded" });

      const filePath = path.join(process.cwd(), req.file.path);
      const results = [];

      fs.createReadStream(filePath)
        .pipe(csv())
        .on("data", (row) => {
          const studentName = row.studentName || row.name;
          const email = row.email;
          const dob = row.dob;
          const course = row.course;
          const rollNo = row.rollNo || row.rollno || row.RollNo;
          const adharNumber = row.adharNumber || row.aadhar || row.Aadhaar || row.Aadhar;

          if (!studentName || !email || !dob || !course || !adharNumber || !rollNo) {
            console.warn("Skipping row due to missing data:", row);
            return;
          }

          results.push({ studentName, email, dob, course, adharNumber, rollNo });
        })
        .on("end", async () => {
          try { fs.unlinkSync(filePath); } catch (e) { console.warn("Failed to delete file:", e.message); }

          const inserted = [];
          for (const row of results) {
            const { studentName, email, dob, course, adharNumber, rollNo } = row;
            try {
              const count = await prisma.certificate.count();
              const certificateId = `Trust${2000 + count + 1}`;
              const adharHash = hashData(adharNumber);

              const encryptedName = encrypt(studentName);
              const encryptedEmail = encrypt(email);
              const encryptedCourse = encrypt(course);

              const blockchainHash = certificateChain.addBlock(
                new Block(certificateChain.chain.length, Date.now().toString(), {
                  certificateId,
                  studentName,
                  email,
                  dob: new Date(dob).toISOString(),
                  course,
                  adharHash,
                  rollNo,
                  college: req.user.name,
                })
              );

              const cert = await prisma.certificate.create({
                data: {
                  certificateId,
                  studentName: encryptedName,
                  email: encryptedEmail,
                  dob: new Date(dob),
                  course: encryptedCourse,
                  adharHash,
                  blockchainHash,
                  rollNo,
                  collegeId: req.user.id,
                },
              });

              inserted.push(cert);
              console.log("Inserted certificate:", cert.certificateId);
            } catch (err) {
              console.error("Error inserting row:", row, err.message);
            }
          }

          res.json({ message: "CSV processed", insertedCount: inserted.length });
        })
        .on("error", (err) => {
          console.error("CSV stream error:", err);
          res.status(500).json({ error: "CSV processing failed" });
        });
    } catch (err) {
      console.error("Server error during CSV upload:", err);
      res.status(500).json({ error: "Server error during upload" });
    }
  }
);


// Verify certificate
app.post("/verify-certificate", async (req, res) => {
  try {
    const { certificateId, adharNumber } = req.body;
    if (!certificateId || !adharNumber)
      return res
        .status(400)
        .json({ error: "Certificate ID and Aadhaar required" });

    const cert = await prisma.certificate.findUnique({
      where: { certificateId },
      include: { college: true },
    });
    if (!cert) return res.status(404).json({ error: "Certificate not found" });

    const inputHash = hashData(adharNumber);
    const adharMatch = cert.adharHash === inputHash;
    const chainValid = certificateChain.isChainValid();

    const block = certificateChain.findBlockByHash(cert.blockchainHash);
    let dataMatch = false;

    if (block) {
      const b = block.data;
      dataMatch =
        b.certificateId === cert.certificateId &&
        b.studentName === decrypt(cert.studentName) &&
        b.email === decrypt(cert.email) &&
        b.dob.split("T")[0] === cert.dob.toISOString().split("T")[0] &&
        b.course === decrypt(cert.course) &&
        b.rollNo === cert.rollNo &&
        b.adharHash === cert.adharHash;
    }

    const verified = adharMatch && chainValid && dataMatch;

    res.json({
      certificateId: cert.certificateId,
      studentName: decrypt(cert.studentName),
      course: decrypt(cert.course),
      rollNo: cert.rollNo,
      adharNumber: cert.adharEncrypted ? decrypt(cert.adharEncrypted) : null,
      collegeName: cert.college?.name || null,
      validAdhar: adharMatch,
      blockchainOk: chainValid,
      dataMatch,
      verified,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Verification failed" });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Server running at http://localhost:${PORT}`)
);
