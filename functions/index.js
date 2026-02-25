const functions = require("firebase-functions");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const { db } = require("./firebaseAdmin");

const app = express();
app.use(cors({ origin: true }));
app.use(express.json());

const JWT_SECRET = "superSecretKey123";

/* ================= REGISTER ================= */
app.post("/auth/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;

    const userRef = db.collection("users").doc(email);
    const userDoc = await userRef.get();

    if (userDoc.exists) {
      return res.status(400).json("User already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await userRef.set({
      name,
      email,
      password: hashedPassword,
      createdAt: new Date()
    });

    res.json("User registered successfully");

  } catch (err) {
    res.status(500).json(err.message);
  }
});

/* ================= LOGIN ================= */
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const userDoc = await db.collection("users").doc(email).get();

    if (!userDoc.exists) {
      return res.status(400).json("User not found");
    }

    const user = userDoc.data();

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json("Invalid credentials");
    }

    const token = jwt.sign(
      { email: user.email },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      token,
      user: {
        name: user.name,
        email: user.email
      }
    });

  } catch (err) {
    res.status(500).json(err.message);
  }
});

/* ================= AUTH MIDDLEWARE ================= */
const auth = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json("No token");

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json("Invalid token");
  }
};

/* ================= CREATE TASK ================= */
app.post("/tasks", auth, async (req, res) => {
  const { title, description, due_date, priority } = req.body;

  const taskRef = await db.collection("tasks").add({
    title,
    description,
    due_date,
    priority,
    status: "Pending",
    email: req.user.email,
    createdAt: new Date()
  });

  res.json({ id: taskRef.id });
});

/* ================= GET TASKS ================= */
app.get("/tasks", auth, async (req, res) => {
  const snapshot = await db
    .collection("tasks")
    .where("email", "==", req.user.email)
    .get();

  const tasks = snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data()
  }));

  res.json(tasks);
});

/* ================= UPDATE TASK ================= */
app.put("/tasks/:id", auth, async (req, res) => {
  await db.collection("tasks").doc(req.params.id).update(req.body);
  res.json("Task updated");
});

/* ================= DELETE TASK ================= */
app.delete("/tasks/:id", auth, async (req, res) => {
  await db.collection("tasks").doc(req.params.id).delete();
  res.json("Task deleted");
});

exports.api = functions.https.onRequest(app);