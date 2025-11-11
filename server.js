require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const app = express();
app.use(express.json());
app.use(cookieParser());


const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const admin = require("firebase-admin");
const jwt = require("jsonwebtoken");

// Firebase Admin Init
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
  }),
});

app.use(cors({ origin: true, credentials: true }));
app.use(passport.initialize());

// Create secure session cookie
function setSession(res, payload) {
  const token = jwt.sign(payload, process.env.SESSION_JWT_SECRET, { expiresIn: "7d" });
  res.cookie("pcp_session", token, {
    httpOnly: true,
    secure: false, // local testing - later true on HTTPS server
    sameSite: "lax",
    maxAge: 7 * 86400 * 1000,
  });
}

// Google Strategy
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
          // create new if not exists
          user = await admin.auth().createUser({
            email,
            displayName: profile.displayName,
            emailVerified: true,
          });
        }

        return done(null, { uid: user.uid, email: user.email });
      } catch (error) {
        done(error);
      }
    }
  )
);

// ✅ Google Login URL (जो तुमने open किया था)
app.get("/auth/google", passport.authenticate("google", { scope: ["email", "profile"] }));

// ✅ Callback (Google के बाद वापस यहाँ आता है)
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { session: false }),
  (req, res) => {
    setSession(res, { uid: req.user.uid, email: req.user.email });

    const returnUrl = req.query.return_url || "https://www.prepcampusplus.com/";
    return res.redirect(returnUrl);
  }
);



// ✅ Email + Password Auth (Add Here)

const FIREBASE_REST = "https://identitytoolkit.googleapis.com/v1";
const FIREBASE_API_KEY = process.env.FIREBASE_WEB_API_KEY;

// SIGNUP
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

    const signInResp = await fetch(`${FIREBASE_REST}/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`, {
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

// LOGIN
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

// ✅ Test route remains below
app.get("/", (req, res) => {
  res.send("✅ PrepCampusPlus Auth Server Working");
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server running → http://localhost:" + PORT);
});
