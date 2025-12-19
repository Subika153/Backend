const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
const SECRET_KEY = "mysecretkey";

app.use(express.json());

// MongoDB connection
mongoose
  .connect("mongodb://127.0.0.1:27017/studentDB")
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.log("Mongo error:", err));

// Student Schema (5 subjects)
const studentSchema = new mongoose.Schema({
  name: { type: String, required: true },
  roll_no: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  subject1: { type: Number, required: true },
  subject2: { type: Number, required: true },
  subject3: { type: Number, required: true },
  subject4: { type: Number, required: true },
  subject5: { type: Number, required: true }
});

const Student = mongoose.model("Student", studentSchema);

// Auth Middleware
const auth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader)
      return res.status(401).json({ message: "Token missing" });

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, SECRET_KEY);
    req.student = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

// Register
app.post("/register", async (req, res) => {
  try {
    const {
      name,
      roll_no,
      password,
      subject1,
      subject2,
      subject3,
      subject4,
      subject5
    } = req.body;

    const exists = await Student.findOne({ roll_no });
    if (exists)
      return res.status(400).json({ message: "Roll number already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    const student = new Student({
      name,
      roll_no,
      password: hashedPassword,
      subject1,
      subject2,
      subject3,
      subject4,
      subject5
    });

    await student.save();
    res.status(201).json({ message: "Student registered successfully" });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { roll_no, password } = req.body;

    const student = await Student.findOne({ roll_no });
    if (!student)
      return res.status(404).json({ message: "Student not found" });

    const match = await bcrypt.compare(password, student.password);
    if (!match)
      return res.status(401).json({ message: "Invalid password" });

    const token = jwt.sign(
      { id: student._id, roll_no: student.roll_no },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.json({ token });

  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Profile
app.get("/profile", auth, async (req, res) => {
  try {
    const student = await Student.findById(req.student.id).select("-password");
    if (!student)
      return res.status(404).json({ message: "Student not found" });

    res.json(student);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
