import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

// --- CONFIGURATION ---
dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// --- DATABASE CONNECTION ---
// In a real app, this might be in its own /config/db.js file
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(MONGO_URI);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Error connecting to MongoDB: ${error.message}`);
    process.exit(1);
  }
};

// =================================================================
// --- MVC PART 1: MODELS ---
// In a real MVC structure, these would be in /models/userModel.js
// and /models/noteModel.js
// =================================================================

// User Schema
const userSchema = mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  },
  {
    timestamps: true,
  }
);

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare entered password with hashed password
userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model("User", userSchema);

// Note Schema
const noteSchema = mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      ref: "User",
    },
    title: { type: String, required: true },
    content: { type: String, required: true },
    tags: [{ type: String }],
  },
  {
    timestamps: true,
  }
);

const Note = mongoose.model("Note", noteSchema);

// =================================================================
// --- MIDDLEWARE ---
// In a real MVC structure, this would be in /middleware/authMiddleware.js
// =================================================================

const protect = async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = await User.findById(decoded.id).select("-password");
      next();
    } catch (error) {
      console.error(error);
      res.status(401).json({ message: "Not authorized, token failed" });
    }
  }

  if (!token) {
    res.status(401).json({ message: "Not authorized, no token" });
  }
};

// =================================================================
// --- MVC PART 2: CONTROLLERS ---
// In a real MVC structure, these would be in /controllers/userController.js
// and /controllers/noteController.js
// =================================================================

// --- User Controllers ---

const generateToken = (id) => {
  return jwt.sign({ id }, JWT_SECRET, {
    expiresIn: "30d",
  });
};

const registerUser = async (req, res) => {
  const { name, email, password } = req.body;
  const userExists = await User.findOne({ email });

  if (userExists) {
    return res.status(400).json({ message: "User already exists" });
  }

  const user = await User.create({ name, email, password });

  if (user) {
    res.status(201).json({
      _id: user._id,
      name: user.name,
      email: user.email,
      token: generateToken(user._id),
    });
  } else {
    res.status(400).json({ message: "Invalid user data" });
  }
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (user && (await user.matchPassword(password))) {
    res.json({
      _id: user._id,
      name: user.name,
      email: user.email,
      token: generateToken(user._id),
    });
  } else {
    res.status(401).json({ message: "Invalid email or password" });
  }
};

// --- Note Controllers ---

const getNotes = async (req, res) => {
  const notes = await Note.find({ user: req.user._id }).sort({ updatedAt: -1 });
  res.json(notes);
};

const createNote = async (req, res) => {
  const { title, content, tags } = req.body;
  if (!title || !content) {
    return res
      .status(400)
      .json({ message: "Please provide title and content" });
  }

  const note = new Note({
    user: req.user._id,
    title,
    content,
    tags: tags || [],
  });

  const createdNote = await note.save();
  res.status(201).json(createdNote);
};

const updateNote = async (req, res) => {
  const { title, content, tags } = req.body;
  const note = await Note.findById(req.params.id);

  if (note && note.user.toString() === req.user._id.toString()) {
    note.title = title || note.title;
    note.content = content || note.content;
    note.tags = tags || note.tags;
    const updatedNote = await note.save();
    res.json(updatedNote);
  } else {
    res.status(404).json({ message: "Note not found or user not authorized" });
  }
};

const deleteNote = async (req, res) => {
  const note = await Note.findById(req.params.id);

  if (note && note.user.toString() === req.user._id.toString()) {
    await note.deleteOne();
    res.json({ message: "Note removed" });
  } else {
    res.status(404).json({ message: "Note not found or user not authorized" });
  }
};

// =================================================================
// --- MVC PART 3: ROUTES ---
// In a real MVC structure, these would be in /routes/userRoutes.js
// and /routes/noteRoutes.js
// =================================================================

// --- User Routes ---
const userRouter = express.Router();
userRouter.post("/register", registerUser);
userRouter.post("/login", loginUser);

// --- Note Routes ---
const noteRouter = express.Router();
noteRouter.route("/").get(protect, getNotes).post(protect, createNote);
noteRouter.route("/:id").put(protect, updateNote).delete(protect, deleteNote);

// Use the routers in the main app
app.use("/api/users", userRouter);
app.use("/api/notes", noteRouter);

// --- START SERVER ---
connectDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
});
