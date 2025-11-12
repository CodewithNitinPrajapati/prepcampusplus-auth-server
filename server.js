require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const helmet = require("helmet");
const compression = require("compression");
const passport = require("passport");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);
app.use(compression());

// ✅ CORS setup
app.use(
  cors({
    origin: [
      "https://www.prepcampusplus.com",
      "https://prepcampusplus.blogspot.com",
      "https://prepcampusplus.onrender.com",
    ],
    credentials: true,
  })
);

// ✅ Firebase Admin Init
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  }),
});

app.use(passport.initialize());

// ✅ Cookie Helper
function setSession(res, payload) {
  const token = jwt.sign(payload, process.env.SESSION_JWT_SECRET, { expiresIn: "7d" });
  res.cookie("pcp_session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
    maxAge: 7 * 86400 * 1000,
  });
}

// ✅ Google OAuth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;

        let user;
        try {
          user = await admin.auth().getUserByEmail(email);
        } catch {
          user = await admin.auth().createUser({
            email,
            displayName: profile.displayName,
            emailVerified: true,
          });
        }

        done(null, { uid: user.uid, email: user.email });
      } catch (error) {
        done(error);
      }
    }
  )
);

app.get("/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {
    setSession(res, { uid: req.user.uid, email: req.user.email });
    const returnUrl = req.query.return_url || "https://www.prepcampusplus.com/";
    res.redirect(returnUrl);
  }
);

// ✅ Firebase REST API Setup
const FIREBASE_REST = "https://identitytoolkit.googleapis.com/v1";
const FIREBASE_API_KEY = process.env.FIREBASE_WEB_API_KEY;

// ✅ Signup
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });

    const user = await admin.auth().createUser({
      email,
      password,
      displayName: name || undefined,
      emailVerified: false,
    });

    await fetch(`${FIREBASE_REST}/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, returnSecureToken: true }),
    });

    setSession(res, { uid: user.uid, email: user.email, provider: "password" });
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.errorInfo?.message || err.message });
  }
});

// ✅ Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const signInResp = await fetch(`${FIREBASE_REST}/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password, returnSecureToken: true }),
    });
    const data = await signInResp.json();
    if (!signInResp.ok) return res.status(401).json({ error: "Invalid email or password" });

    setSession(res, { uid: data.localId, email, provider: "password" });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: "Server Error" });
  }
});

// ✅ Auth Check
app.get("/api/auth/me", async (req, res) => {
  try {
    const token = req.cookies.pcp_session;
    if (!token) return res.status(401).json({ authenticated: false });

    const decoded = jwt.verify(token, process.env.SESSION_JWT_SECRET);
    const user = await admin.auth().getUser(decoded.uid);

    res.json({
      authenticated: true,
      user: {
        uid: user.uid,
        email: user.email,
        name: user.displayName || "",
        provider: decoded.provider || "unknown",
      },
    });
  } catch {
    res.status(401).json({ authenticated: false });
  }
});

// ✅ Logout
app.post("/api/logout", (req, res) => {
  try {
    res.clearCookie("pcp_session", {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      path: "/",
    });
    res.json({ ok: true });
  } catch {
    res.status(500).json({ ok: false });
  }
});

// ✅ 404 Fallback
app.use((req, res) => res.status(404).json({ error: "Route not found" }));

// ✅ Health Check
app.get("/", (req, res) => res.send("✅ PrepCampusPlus Auth Server Working"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running → http://localhost:${PORT}`));
