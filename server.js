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
const fetch = (...args) =>
  import("node-fetch").then(({ default: fetch }) => fetch(...args));

const app = express();

/* =========================
   BASIC MIDDLEWARE
========================= */
app.use(express.json());
app.use(cookieParser());
app.use(
  helmet({
    crossOriginResourcePolicy: false,
  })
);
app.use(compression());

/* =========================
   CORS (STRICT)
========================= */
const FRONTEND_ORIGIN = "https://prepcampusplus.com";

app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
  })
);

/* =========================
   FIREBASE ADMIN INIT
========================= */
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  }),
});

app.use(passport.initialize());

/* =========================
   HEALTH CHECK (IMPORTANT)
========================= */
app.get("/", (req, res) => {
  res.send("✅ PrepCampusPlus Auth Server Working");
});

/* =========================
   COOKIE SESSION HELPER
========================= */
function setSession(res, payload) {
  const token = jwt.sign(payload, process.env.SESSION_JWT_SECRET, {
    expiresIn: "7d",
  });

  res.cookie("pcp_session", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    domain:
      process.env.NODE_ENV === "production"
        ? ".prepcampusplus.com"
        : undefined,
    path: "/",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

/* =========================
   GOOGLE OAUTH
========================= */
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:
        process.env.NODE_ENV === "production"
          ? "https://auth.prepcampusplus.com/auth/google/callback"
          : "http://localhost:3000/auth/google/callback",
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
      } catch (err) {
        done(err);
      }
    }
  )
);

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["email", "profile"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {
    setSession(res, {
      uid: req.user.uid,
      email: req.user.email,
      provider: "google",
    });

    let returnUrl = req.query.return_url || "/campus-control";

    // 🔐 Security: only allow same-site redirects
    if (!returnUrl.startsWith("/")) {
      returnUrl = "/campus-control";
    }

    res.redirect(returnUrl);
  }
);


/* =========================
   FIREBASE REST AUTH
========================= */
const FIREBASE_REST = "https://identitytoolkit.googleapis.com/v1";
const FIREBASE_API_KEY = process.env.FIREBASE_WEB_API_KEY;

/* =========================
   SIGNUP
========================= */
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });

    const user = await admin.auth().createUser({
      email,
      password,
      displayName: name || undefined,
      emailVerified: false,
    });

    await fetch(
      `${FIREBASE_REST}/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          password,
          returnSecureToken: true,
        }),
      }
    );

    setSession(res, {
      uid: user.uid,
      email: user.email,
      provider: "password",
    });

    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

/* =========================
   LOGIN
========================= */
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const resp = await fetch(
      `${FIREBASE_REST}/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          password,
          returnSecureToken: true,
        }),
      }
    );

    if (!resp.ok)
      return res.status(401).json({ error: "Invalid email or password" });

    const data = await resp.json();

    setSession(res, {
      uid: data.localId,
      email,
      provider: "password",
    });

    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: "Server error" });
  }
});

/* =========================
   AUTH CHECK
========================= */
app.get("/api/auth/me", async (req, res) => {
  try {
    const token = req.cookies.pcp_session;
    if (!token)
      return res.status(401).json({ authenticated: false });

    const decoded = jwt.verify(token, process.env.SESSION_JWT_SECRET);
    const user = await admin.auth().getUser(decoded.uid);

    res.json({
      authenticated: true,
      user: {
        uid: user.uid,
        email: user.email,
        name: user.displayName || "",
        provider: decoded.provider,
      },
    });
  } catch {
    res.status(401).json({ authenticated: false });
  }
});

/* =========================
   LOGOUT
========================= */
app.post("/api/logout", (req, res) => {
  res.clearCookie("pcp_session", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    domain:
      process.env.NODE_ENV === "production"
        ? ".prepcampusplus.com"
        : undefined,
    path: "/",
  });
  res.json({ ok: true });
});

/* =========================
   404 FALLBACK (ALWAYS LAST)
========================= */
app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`🚀 Auth server running on port ${PORT}`)
);
