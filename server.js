const express = require("express");
const { MongoClient, ServerApiVersion } = require("mongodb");
const dotenv = require("dotenv");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;
// Middleware
app.use(express.json());
app.use(cookieParser());
const corsOption = {
  origin: ["http://localhost:3000"],
  credentials: true,
};
app.use(cors(corsOption));
// MongoDB Connection
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// middleware
const authenticate = (req, res, next) => {
  const token = req.cookies.token || req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "No token" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ message: "Invalid token" });
  }
};
async function run() {
  try {
    const usersCollection = client.db("islamic-quotes").collection("users");

    // check user
    app.get("/me", authenticate, (req, res) => {
      res.json({ authenticate: true, user: req.user });
    });

    // user logout
    app.post("/logout", (req, res) => {
      res.clearCookie("token", {
        httpOnly: true,
        sameSite: "lax",
        secure: false, // true only in production with https
        path: "/", // IMPORTANT: must match cookie path
      });
      res.json({ message: "Logged out" });
    });

    app.post("/register", async (req, res) => {
      try {
        // const { name, email, password, photo } = req.body;

        const existUser = await usersCollection.findOne({ email });
        if (existUser) {
          return res.status(404).json({ message: "Email already registered" });
        }
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = {
          name,
          email,
          password: hashedPassword,
          role: "user",
          photo: photo || "",
          crateAt: new Date(),
          updateAt: new Date(),
        };
        await usersCollection.insertOne(newUser);
        res
          .status(201)
          .json({ message: "User registered successfully", user: newUser });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    app.post("/login", async (req, res) => {
      try {
        const { email, password } = req.body;
        console.log(email, password);
        // check if user exist
        const user = await usersCollection.findOne({ email });
        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }
        // compare password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
          return res.status(401).json({ message: "Invalid password" });
        }

        // create token
        const token = jwt.sign(
          { id: user._id, email: user.email },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
        );
        // set cookie
        res.cookie("token", token, {
          httpOnly: true,
          secure: false,
          sameSite: "lax",
          maxAge: 60 * 60 * 1000,
        });
        res.status(200).json({
          message: "Login successful",
          user: {
            name: user.name,
            email: user.email,
            role: user.role,
            photo: user.photo,
          },
        });
      } catch (error) {
        res.status(500).json({ message: error.message });
      }
    });

    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Server is running......");
});

app.listen(PORT, () => {
  console.log(`server listening on port ${PORT}`);
});
