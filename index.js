// index.js
require("dotenv").config();
const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const admin = require("firebase-admin");
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const app = express();

// ---------- CORS / Body parsing ----------
// Keep webhook raw; other routes use JSON. We'll register webhook route with bodyParser.raw.
// For normal endpoints:
app.use(cors({ origin: process.env.FRONTEND_URL || true }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json()); // for all regular JSON requests

// ---------- Firebase Admin (optional) ----------
try {
  const firebaseConfig = {
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY
      ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
      : undefined,
  };
  if (
    firebaseConfig.projectId &&
    firebaseConfig.clientEmail &&
    firebaseConfig.privateKey
  ) {
    admin.initializeApp({
      credential: admin.credential.cert(firebaseConfig),
    });
    console.log("Firebase admin initialized");
  } else {
    console.log("Firebase admin not fully configured (skipping init)");
  }
} catch (err) {
  console.error("Firebase init error (continuing):", err.message);
}

// ---------- MongoDB ----------
const client = new MongoClient(process.env.MONGO_URI, {});
let db;
async function startDb() {
  try {
    // await client.connect();
    db = client.db(process.env.MONGO_DB_NAME || "scholarStreamDB");
    console.log("Connected to MongoDB:", db.databaseName);
  } catch (err) {
    console.error("DB Connection Error:", err);
  }
}
startDb();

// ---------- Helpers: JWT ----------
function signJWT(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "7d",
  });
}

function verifyJWT(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth)
    return res.status(401).json({ message: "Missing authorization header" });
  const token = auth.split(" ")[1];
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = decoded; // { uid, email, role, name, ... } depending on how you signed
    next();
  });
}

// Role middlewares
async function verifyAdmin(req, res, next) {
  try {
    const email = req.user?.email;
    if (!email) return res.status(403).json({ message: "Forbidden" });
    const user = await db.collection("users").findOne({ email });
    if (user?.role === "Admin") return next();
    return res.status(403).json({ message: "Admin access required" });
  } catch (err) {
    console.error("verifyAdmin error:", err);
    return res.status(500).json({ message: "Server error" });
  }
}
async function verifyModerator(req, res, next) {
  try {
    const email = req.user?.email;
    if (!email) return res.status(403).json({ message: "Forbidden" });
    const user = await db.collection("users").findOne({ email });
    if (user?.role === "Moderator" || user?.role === "Admin") return next();
    return res.status(403).json({ message: "Moderator access required" });
  } catch (err) {
    console.error("verifyModerator error:", err);
    return res.status(500).json({ message: "Server error" });
  }
}

// ---------- Basic routes ----------
app.get("/", (req, res) =>
  res.send("Scholarship Management Server is running")
);

// ---------- AUTH (simple) ----------
app.post("/auth/register-user", async (req, res) => {
  try {
    const { name, email, country, phone, dob, college, photoURL } = req.body;
    if (!name || !email || !country || !phone || !dob || !college) {
      return res.status(400).json({ message: "All fields are required" });
    }
    const usersColl = db.collection("users");
    const existing = await usersColl.findOne({ email });
    if (existing)
      return res.status(400).json({ message: "User already exists" });

    const newUser = {
      name,
      email,
      country,
      phone,
      dob,
      college,
      photoURL: photoURL || "",
      role: "Student",
      createdAt: new Date(),
    };
    const result = await usersColl.insertOne(newUser);
    res.json({
      message: "User profile saved",
      userId: result.insertedId,
      user: newUser,
    });
  } catch (error) {
    console.error("register-user error:", error);
    res.status(500).json({ message: "Server error creating user" });
  }
});

// Firebase login -> issue backend JWT (expects idToken from client)
app.post("/auth/firebase-login", async (req, res) => {
  const { idToken } = req.body;
  if (!idToken) return res.status(400).json({ message: "idToken missing" });

  try {
    if (!admin.apps.length)
      return res.status(500).json({ message: "Firebase not configured" });
    const decoded = await admin.auth().verifyIdToken(idToken);
    const { uid, email } = decoded;
    const usersColl = db.collection("users");
    const user = await usersColl.findOne({ email });
    if (!user)
      return res.status(404).json({
        message: "User profile not found. Please complete registration.",
      });
    const token = signJWT({ uid, email, role: user.role, name: user.name });
    res.json({ token, user: { ...user, uid } });
  } catch (err) {
    console.error("firebase-login err:", err);
    res.status(401).json({ message: "Firebase login failed" });
  }
});

// ---------- USERS (admin) ----------
app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const users = await db.collection("users").find({}).toArray();
    res.json(users);
  } catch (err) {
    console.error("GET /users error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/users/:id/role", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    const { role } = req.body;
    if (!["Student", "Moderator", "Admin"].includes(role)) {
      return res.status(400).json({ message: "Invalid role" });
    }
    const r = await db
      .collection("users")
      .updateOne({ _id: new ObjectId(id) }, { $set: { role } });
    res.json({ modifiedCount: r.modifiedCount });
  } catch (err) {
    console.error("PATCH /users/:id/role", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/users/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;

    await db.collection("users").deleteOne({ _id: new ObjectId(id) });

    // Optional: also remove the user's applications & reviews
    await db.collection("applications").deleteMany({ userId: id });
    await db.collection("reviews").deleteMany({ userId: id });

    res.json({ success: true });
  } catch (err) {
    console.error("DELETE USER ERROR:", err);
    res.status(500).json({ message: "Could not delete user" });
  }
});

app.patch("/users/:id", async (req, res) => {
  try {
    const { id } = req.params;

    // Validate ID
    if (!ObjectId.isValid(id)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid user ID" });
    }

    const oid = new ObjectId(id);
    const usersColl = db.collection("users");

    const updatedData = {
      name: req.body.name,
      country: req.body.country,
      phone: req.body.phone,
      dob: req.body.dob,
      college: req.body.college,
      photoURL: req.body.photoURL,
      updatedAt: new Date(),
    };

    await usersColl.updateOne({ _id: oid }, { $set: updatedData });

    const updatedUser = await usersColl.findOne({ _id: oid });

    return res.status(200).json({
      success: true,
      message: "Profile updated",
      user: updatedUser,
    });
  } catch (err) {
    console.error("update-user error:", err);
    return res.status(500).json({
      success: false,
      message: "Error updating profile",
    });
  }
});

// ---------- SCHOLARSHIPS ----------
// Latest 10 public
app.get("/scholarships-latest", async (req, res) => {
  try {
    const items = await db
      .collection("scholarships")
      .find({})
      .sort({ scholarshipPostDate: -1 })
      .limit(10)
      .toArray();
    res.json(items);
  } catch (error) {
    console.error("Latest scholarships error:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Create (Admin/Moderator)
app.post("/scholarships", verifyJWT, verifyModerator, async (req, res) => {
  try {
    const doc = {
      scholarshipName: req.body.scholarshipName || "",
      universityName: req.body.universityName || "",
      universityImage: req.body.universityImage || "",
      universityCountry: req.body.universityCountry || "",
      universityCity: req.body.universityCity || "",
      universityWorldRank: req.body.universityWorldRank || "",
      subjectCategory: req.body.subjectCategory || "",
      scholarshipCategory: req.body.scholarshipCategory || "",
      degree: req.body.degree || "",
      applicationFees: Number(req.body.applicationFees || 0),
      serviceCharge: Number(req.body.serviceCharge || 0),
      applicationDeadline: req.body.applicationDeadline || "",
      scholarshipDescription: req.body.scholarshipDescription || "",
      stipendCoverage: req.body.stipendCoverage || "",
      tuitionFees: req.body.tuitionFees || "",
      eligibilityCriteria: req.body.eligibilityCriteria || "",
      requiredDocuments: req.body.requiredDocuments || "",
      location: req.body.location || "",
      scholarshipPostDate: new Date(),
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    const r = await db.collection("scholarships").insertOne(doc);
    res.json({
      success: true,
      message: "Scholarship created",
      insertedId: r.insertedId,
    });
  } catch (error) {
    console.error("POST /scholarships error:", error);
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// Get single scholarship
app.get("/scholarships/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id))
      return res.status(400).json({ message: "Invalid ID format" });
    const doc = await db
      .collection("scholarships")
      .findOne({ _id: new ObjectId(id) });
    if (!doc) return res.status(404).json({ message: "Scholarship not found" });
    res.json(doc);
  } catch (error) {
    console.error("GET /scholarships/:id error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Update (Admin)
app.put("/scholarships/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id))
      return res.status(400).json({ message: "Invalid scholarship ID" });

    const updateDoc = {
      scholarshipName: req.body.scholarshipName || "",
      universityName: req.body.universityName || "",
      universityImage: req.body.universityImage || "",
      universityCountry: req.body.universityCountry || "",
      universityCity: req.body.universityCity || "",
      universityWorldRank: req.body.universityWorldRank || "",
      subjectCategory: req.body.subjectCategory || "",
      scholarshipCategory: req.body.scholarshipCategory || "",
      degree: req.body.degree || "",
      applicationFees: Number(req.body.applicationFees || 0),
      serviceCharge: Number(req.body.serviceCharge || 0),
      applicationDeadline: req.body.applicationDeadline || "",
      scholarshipDescription: req.body.scholarshipDescription || "",
      stipendCoverage: req.body.stipendCoverage || "",
      tuitionFees: req.body.tuitionFees || "",
      eligibilityCriteria: req.body.eligibilityCriteria || "",
      requiredDocuments: req.body.requiredDocuments || "",
      location: req.body.location || "",
      updatedAt: new Date(),
    };

    const result = await db
      .collection("scholarships")
      .updateOne({ _id: new ObjectId(id) }, { $set: updateDoc });
    if (result.modifiedCount === 0) {
      return res
        .status(404)
        .json({ message: "Scholarship not found or no changes detected" });
    }
    res.json({
      success: true,
      message: "Scholarship updated",
      modifiedCount: result.modifiedCount,
    });
  } catch (error) {
    console.error("PUT /scholarships/:id error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Delete (Admin)
app.delete("/scholarships/:id", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id))
      return res.status(400).json({ message: "Invalid ID" });
    const r = await db
      .collection("scholarships")
      .deleteOne({ _id: new ObjectId(id) });
    res.json({ deletedCount: r.deletedCount });
  } catch (err) {
    console.error("DELETE /scholarships/:id", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Search/list with filters (pagination)
app.get("/scholarships", async (req, res) => {
  try {
    const q = req.query.q || "";
    const country = req.query.country;
    const category = req.query.category;
    const degree = req.query.degree;
    const sortBy = req.query.sortBy || "scholarshipPostDate";
    const sortDir = req.query.sortDir === "asc" ? 1 : -1;
    const page = Math.max(1, parseInt(req.query.page || "1"));
    const limit = Math.max(1, parseInt(req.query.limit || "10"));
    const skip = (page - 1) * limit;
    const filter = {};
    if (q) {
      filter.$or = [
        { scholarshipName: new RegExp(q, "i") },
        { universityName: new RegExp(q, "i") },
        { degree: new RegExp(q, "i") },
        { subjectCategory: new RegExp(q, "i") },
        { scholarshipCategory: new RegExp(q, "i") },
      ];
    }
    if (country) filter.universityCountry = new RegExp(`^${country}$`, "i");
    if (category) filter.scholarshipCategory = category;
    if (degree) filter.degree = degree;
    const sort = {};
    sort[sortBy] = sortDir;
    const coll = db.collection("scholarships");
    const results = await coll
      .find(filter)
      .sort(sort)
      .skip(skip)
      .limit(limit)
      .toArray();
    const total = await coll.countDocuments(filter);
    return res.json({
      total,
      page,
      limit,
      totalPages: Math.ceil(total / limit),
      results,
    });
  } catch (error) {
    console.error("GET /scholarships error →", error);
    return res.status(500).json({ message: "Server error" });
  }
});

// ---------- APPLICATIONS ----------
// Create application (student). Frontend may call this BEFORE payment to generate application record.
// If you prefer create-on-checkout, see /create-checkout-session which can create application when needed.
app.post("/applications", verifyJWT, async (req, res) => {
  try {
    const dbApp = db.collection("applications");
    const body = req.body;

    // validate scholarshipId
    let scholarshipObjectId;
    try {
      scholarshipObjectId = new ObjectId(body.scholarshipId);
    } catch (e) {
      return res.status(400).json({ message: "Invalid scholarshipId" });
    }

    const newApplication = {
      scholarshipId: scholarshipObjectId,

      // 🔥 FIXED: userId is NOT ObjectId
      userId: req.user.uid,
      userName: body.userName,
      userEmail: body.userEmail,

      universityImage: body.universityImage || "",
      universityName: body.universityName,
      universityCountry: body.universityCountry,

      formData: body.formData || {},

      scholarshipName: body.scholarshipName,

      applicationFees: Number(body.applicationFees),
      serviceCharge: Number(body.serviceCharge),
      totalAmount: Number(body.totalAmount),

      paymentStatus: "unpaid",
      applicationStatus: "pending",
      applicationDate: new Date(),
    };

    const result = await dbApp.insertOne(newApplication);

    return res.json({ success: true, insertedId: result.insertedId });
  } catch (err) {
    console.error("SERVER ERROR:", err);
    return res.status(500).json({ message: "Server crashed" });
  }
});

// Get applications for a student (by email)
// NOTE: verifyJWT ensures the user is authenticated; you might want to confirm req.user.email === params.email or restrict to own user
app.get("/applications/student/:email", verifyJWT, async (req, res) => {
  try {
    const email = req.params.email;
    // only allow fetching if requester matches email OR is moderator/admin
    if (req.user?.email !== email) {
      // check role
      const user = await db
        .collection("users")
        .findOne({ email: req.user?.email });
      if (!user || (user.role !== "Moderator" && user.role !== "Admin")) {
        return res.status(403).json({ message: "Forbidden" });
      }
    }
    const apps = await db
      .collection("applications")
      .find({ userEmail: email })
      .sort({ applicationDate: -1 })
      .toArray();
    res.json(apps);
  } catch (err) {
    console.error("GET /applications/student/:email", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Moderator/Admin: get all applications
app.get("/applications", verifyJWT, verifyModerator, async (req, res) => {
  try {
    const apps = await db
      .collection("applications")
      .find({})
      .sort({ applicationDate: -1 })
      .toArray();
    res.json(apps);
  } catch (err) {
    console.error("GET /applications", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch(
  "/applications/complete/:id",
  verifyJWT,
  verifyModerator,
  async (req, res) => {
    try {
      const id = req.params.id;

      const r = await db
        .collection("applications")
        .updateOne(
          { _id: new ObjectId(id) },
          { $set: { applicationStatus: "completed", completedAt: new Date() } }
        );

      res.json({ success: true, modifiedCount: r.modifiedCount });
    } catch (err) {
      console.error("PATCH complete", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// Approve / Reject (moderator)
app.patch(
  "/applications/approve/:id",
  verifyJWT,
  verifyModerator,
  async (req, res) => {
    try {
      const id = req.params.id;
      const r = await db
        .collection("applications")
        .updateOne(
          { _id: new ObjectId(id) },
          { $set: { applicationStatus: "approved" } }
        );
      res.json({ success: true, modifiedCount: r.modifiedCount });
    } catch (err) {
      console.error("PATCH approve", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);
app.patch(
  "/applications/reject/:id",
  verifyJWT,
  verifyModerator,
  async (req, res) => {
    try {
      const id = req.params.id;
      const r = await db
        .collection("applications")
        .updateOne(
          { _id: new ObjectId(id) },
          { $set: { applicationStatus: "rejected" } }
        );
      res.json({ success: true, modifiedCount: r.modifiedCount });
    } catch (err) {
      console.error("PATCH reject", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.delete("/applications/:id", verifyJWT, async (req, res) => {
  try {
    const id = req.params.id;
    const r = await db
      .collection("applications")
      .deleteOne({ _id: new ObjectId(id) });
    res.json({ success: true, deletedCount: r.deletedCount });
  } catch (err) {
    console.error("DELETE application", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get single application
app.get("/applications/:id", verifyJWT, async (req, res) => {
  try {
    const id = req.params.id;
    if (!ObjectId.isValid(id))
      return res.status(400).json({ message: "Invalid ID" });
    const doc = await db
      .collection("applications")
      .findOne({ _id: new ObjectId(id) });
    if (!doc) return res.status(404).json({ message: "Not found" });
    res.json(doc);
  } catch (err) {
    console.error("GET /applications/:id", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------- REVIEWS ----------
app.post("/reviews", verifyJWT, async (req, res) => {
  try {
    const body = req.body;
    const newReview = {
      scholarshipId: new ObjectId(body.scholarshipId),
      universityName: body.universityName || "",
      userId: req.user?.uid || null,
      userName: body.userName || req.user?.name || "",
      userEmail: body.userEmail || req.user?.email || "",
      userImage: body.userImage || "",
      ratingPoint: Number(body.ratingPoint),
      reviewComment: body.reviewComment || "",
      reviewDate: new Date(),
    };
    const result = await db.collection("reviews").insertOne(newReview);
    res.json({ success: true, insertedId: result.insertedId });
  } catch (err) {
    console.error("POST /reviews", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/reviews/:scholarshipId", async (req, res) => {
  try {
    const id = req.params.scholarshipId;
    const reviews = await db
      .collection("reviews")
      .find({ scholarshipId: new ObjectId(id) })
      .sort({ reviewDate: -1 })
      .toArray();
    res.json(reviews);
  } catch (err) {
    console.error("GET /reviews/:scholarshipId", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/reviews", verifyJWT, verifyModerator, async (req, res) => {
  try {
    const reviews = await db
      .collection("reviews")
      .find({})
      .sort({ reviewDate: -1 })
      .toArray();

    res.json(reviews);
  } catch (err) {
    console.error("GET /reviews error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/reviews/:id", verifyJWT, async (req, res) => {
  try {
    const id = req.params.id;

    if (!ObjectId.isValid(id))
      return res.status(400).json({ message: "Invalid review ID" });

    const review = await db
      .collection("reviews")
      .findOne({ _id: new ObjectId(id) });

    if (!review) return res.status(404).json({ message: "Review not found" });

    // Allow delete if:
    // 1. Student deleting own review
    // 2. Moderator/Admin deleting inappropriate content
    const user = await db
      .collection("users")
      .findOne({ email: req.user.email });

    if (review.userEmail !== req.user.email && user.role === "Student") {
      return res.status(403).json({ message: "Not allowed" });
    }

    await db.collection("reviews").deleteOne({ _id: new ObjectId(id) });

    res.json({ success: true });
  } catch (err) {
    console.error("DELETE /reviews/:id error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Moderator adds feedback to an application
app.patch(
  "/applications/:id/feedback",
  verifyJWT,
  verifyModerator,
  async (req, res) => {
    try {
      const id = req.params.id;
      const { feedback } = req.body;

      const r = await db.collection("applications").updateOne(
        { _id: new ObjectId(id) },
        {
          $set: {
            feedback,
            feedbackDate: new Date(),
          },
        }
      );

      res.json({ success: true, modifiedCount: r.modifiedCount });
    } catch (err) {
      console.error("PATCH feedback error:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

// ---------- ANALYTICS (admin) ----------
app.get("/analytics/summary", verifyJWT, verifyAdmin, async (req, res) => {
  try {
    const usersCount = await db.collection("users").countDocuments();
    const scholarshipsCount = await db
      .collection("scholarships")
      .countDocuments();
    const applicationsCount = await db
      .collection("applications")
      .countDocuments();
    const paidApplications = await db
      .collection("applications")
      .countDocuments({ paymentStatus: "paid" });
    res.json({
      usersCount,
      scholarshipsCount,
      applicationsCount,
      paidApplications,
    });
  } catch (err) {
    console.error("GET /analytics/summary", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get(
  "/analytics/applications-by-university",
  verifyJWT,
  verifyAdmin,
  async (req, res) => {
    try {
      const pipeline = [
        {
          $group: {
            _id: "$universityName",
            count: { $sum: 1 },
          },
        },
        { $sort: { count: -1 } },
      ];

      const data = await db
        .collection("applications")
        .aggregate(pipeline)
        .toArray();
      res.json(data);
    } catch (err) {
      console.error("University analytics error:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);
app.get(
  "/analytics/applications-by-category",
  verifyJWT,
  verifyAdmin,
  async (req, res) => {
    try {
      const pipeline = [
        {
          $lookup: {
            from: "scholarships",
            localField: "scholarshipId",
            foreignField: "_id",
            as: "schData",
          },
        },
        { $unwind: "$schData" },
        {
          $group: {
            _id: "$schData.scholarshipCategory",
            count: { $sum: 1 },
          },
        },
        { $sort: { count: -1 } },
      ];

      const data = await db
        .collection("applications")
        .aggregate(pipeline)
        .toArray();
      res.json(data);
    } catch (err) {
      console.error("Category analytics error:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
);

app.get(
  "/analytics/top-scholarships",
  verifyJWT,
  verifyAdmin,
  async (req, res) => {
    try {
      const pipeline = [
        { $group: { _id: "$scholarshipId", totalApplications: { $sum: 1 } } },
        { $sort: { totalApplications: -1 } },
        { $limit: 5 },
      ];

      const data = await db
        .collection("applications")
        .aggregate(pipeline)
        .toArray();
      res.json(data);
    } catch (error) {
      res.status(500).json({ message: "Server error" });
    }
  }
);

// ---------- STRIPE: PaymentIntent (optional) ----------
app.post("/create-payment-intent", verifyJWT, async (req, res) => {
  try {
    const { amount, currency = "usd", applicationId } = req.body;
    if (!amount || amount <= 0)
      return res.status(400).json({ message: "Invalid amount" });
    const paymentIntent = await stripe.paymentIntents.create({
      amount: Math.round(amount), // in cents
      currency,
      metadata: {
        applicationId: applicationId || "none",
        userEmail: req.user?.email,
      },
    });
    res.json({
      clientSecret: paymentIntent.client_secret,
      paymentIntentId: paymentIntent.id,
    });
  } catch (err) {
    console.error("create-payment-intent err:", err);
    res.status(500).json({ message: "Stripe error" });
  }
});

/**
 * /create-checkout-session
 * Accepts:
 *  - applicationId (if existing application created on server)
 * OR
 *  - scholarshipId + form + amount (frontend can submit form + amount, we create application then session)
 *
 * Returns { url, id }
 */
app.post("/create-checkout-session", verifyJWT, async (req, res) => {
  try {
    const { applicationId } = req.body;

    if (!applicationId || !ObjectId.isValid(applicationId)) {
      return res.status(400).json({ message: "Invalid applicationId" });
    }

    const appDoc = await db
      .collection("applications")
      .findOne({ _id: new ObjectId(applicationId) });

    if (!appDoc)
      return res.status(404).json({ message: "Application not found" });

    const totalAmount = Math.round(Number(appDoc.totalAmount || 0) * 100);

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      line_items: [
        {
          price_data: {
            currency: "usd",
            unit_amount: totalAmount,
            product_data: {
              name: `${appDoc.scholarshipName} — Application Fee`,
              images: appDoc.universityImage ? [appDoc.universityImage] : [],
            },
          },
          quantity: 1,
        },
      ],
      metadata: {
        applicationId: appDoc._id.toString(),
        userEmail: appDoc.userEmail,
      },
      success_url: `${process.env.FRONTEND_URL}/application-success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/dashboard/my-applications`,
    });

    res.json({ url: session.url, id: session.id });
  } catch (err) {
    console.error("Error creating checkout session:", err);
    res.status(500).json({ message: "Payment session failed" });
  }
});

// ---------- STRIPE WEBHOOK (raw body required) ----------

const bodyParser = require("body-parser");

// MUST COME BEFORE ANY app.use(express.json())
app.post(
  "/webhook",
  bodyParser.raw({ type: "application/json" }),
  async (req, res) => {
    const sig = req.headers["stripe-signature"];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
      console.error("Missing STRIPE_WEBHOOK_SECRET");
      return res.status(400).send("Webhook secret missing");
    }

    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
      console.error("Invalid webhook signature:", err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // --------------------
    // HANDLE EVENT
    // --------------------
    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const applicationId = session.metadata?.applicationId;

      console.log("Webhook received → Application:", applicationId);

      if (applicationId && ObjectId.isValid(applicationId)) {
        await db.collection("applications").updateOne(
          { _id: new ObjectId(applicationId) },
          {
            $set: {
              paymentStatus: "paid",
              applicationStatus: "processing",
              paymentInfo: {
                sessionId: session.id,
                paymentIntentId: session.payment_intent,
                amountPaid: (session.amount_total || 0) / 100,
                currency: session.currency,
                method: session.payment_method_types || [],
                paidAt: new Date(),
              },
            },
          }
        );

        console.log("Webhook: Payment updated ✔");
      } else {
        console.warn("⚠ No valid applicationId in session metadata");
      }
    }

    res.json({ received: true });
  }
);

app.post("/payment-success", async (req, res) => {
  try {
    const { sessionId } = req.body;

    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const applicationId = session.metadata.applicationId;

    if (!applicationId || !ObjectId.isValid(applicationId)) {
      return res.status(400).json({ message: "Invalid applicationId" });
    }

    await db.collection("applications").updateOne(
      { _id: new ObjectId(applicationId) },
      {
        $set: {
          paymentStatus: "paid",
          paymentDate: new Date(),
          stripePaymentId: session.payment_intent,
        },
      }
    );

    return res.json({ success: true });
  } catch (err) {
    console.error("payment-success error:", err);
    return res.status(500).json({ message: "Failed to update payment status" });
  }
});

// GET ALL SUCCESSFUL PAYMENTS FOR A STUDENT
app.get("/payments/student/:email", verifyJWT, async (req, res) => {
  try {
    const dbApp = db.collection("applications");
    const email = req.params.email;

    const payments = await dbApp
      .find({ userEmail: email, paymentStatus: "paid" })
      .sort({ applicationDate: -1 })
      .toArray();

    return res.json(payments);
  } catch (err) {
    console.error("PAYMENTS FETCH ERROR:", err);
    res.status(500).json({ message: "Failed to fetch payment history" });
  }
});

// Get all reviews by logged-in student
app.get("/my-reviews", verifyJWT, async (req, res) => {
  try {
    const email = req.user.email;

    const reviews = await db
      .collection("reviews")
      .find({ userEmail: email })
      .sort({ reviewDate: -1 })
      .toArray();

    res.json(reviews);
  } catch (err) {
    console.error("GET /my-reviews error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.put("/reviews/:id", verifyJWT, async (req, res) => {
  try {
    const id = req.params.id;
    const { ratingPoint, reviewComment } = req.body;

    if (!ObjectId.isValid(id))
      return res.status(400).json({ message: "Invalid review ID" });

    const review = await db
      .collection("reviews")
      .findOne({ _id: new ObjectId(id) });

    if (!review) return res.status(404).json({ message: "Review not found" });

    // Ensure student can edit only their own review
    if (review.userEmail !== req.user.email) {
      return res.status(403).json({ message: "Not allowed" });
    }

    await db.collection("reviews").updateOne(
      { _id: new ObjectId(id) },
      {
        $set: {
          ratingPoint: Number(ratingPoint),
          reviewComment,
          updatedAt: new Date(),
        },
      }
    );

    res.json({ success: true });
  } catch (err) {
    console.error("PUT /reviews/:id error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

app.delete("/reviews/:id", verifyJWT, async (req, res) => {
  try {
    const id = req.params.id;

    if (!ObjectId.isValid(id))
      return res.status(400).json({ message: "Invalid review ID" });

    const review = await db
      .collection("reviews")
      .findOne({ _id: new ObjectId(id) });

    if (!review) return res.status(404).json({ message: "Review not found" });

    if (review.userEmail !== req.user.email) {
      return res.status(403).json({ message: "Not allowed" });
    }

    await db.collection("reviews").deleteOne({ _id: new ObjectId(id) });

    res.json({ success: true });
  } catch (err) {
    console.error("DELETE /reviews/:id error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------- FINISH / START ----------
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
