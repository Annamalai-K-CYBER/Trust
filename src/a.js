import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";

const prisma = new PrismaClient();

async function main() {
  const hashedPassword = await bcrypt.hash("Admin@123", 10);

  await prisma.admin.create({
    data: {
      email: "admin@trustdegree.com",
      password: hashedPassword,
    },
  });

  console.log("✅ Admin created: admin@trustdegree.com / Admin@123");
}

main()
  .catch((e) => console.error(e))
  .finally(() => prisma.$disconnect());
