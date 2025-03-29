require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const session = require("express-session");
const cors = require("cors");
const stripe = require('stripe')(process.env.STRIPE_SECREAT ?? "");

const app = express();

app.use(express.json());

const frontendURL =
  process.env.NODE_ENV === "production"
    ? "https://www.siam10winery.com"
    : "http://127.0.0.1:5500";

app.use(cors({ origin: frontendURL, credentials: true }));

mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: String,
  address: String,
  phone: String,
  age: Number,
  gender: String,
  googleId: { type: String, unique: true, sparse: true },
  facebookId: { type: String, unique: true, sparse: true },
});
const User = mongoose.model("User", UserSchema);

app.use(
  session({
    secret: process.env.SESSION_SECRET || "some secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {

          user = await User.findOne({ email: profile.emails[0].value });
          if (user) {
            user.googleId = profile.id;
            user.name = profile.displayName;
            await user.save();
          } else {
            user = await User.create({
              googleId: profile.id,
              name: profile.displayName,
              email: profile.emails[0].value,
              password: "",
            });
          }
        }

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL:
        process.env.FACEBOOK_CALLBACK_URL || "/auth/facebook/callback",
      profileFields: ["id", "displayName", "emails"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ facebookId: profile.id });
        if (!user) {
          const email =
            profile.emails && profile.emails[0] ? profile.emails[0].value : "";
          if (email) {
            user = await User.findOne({ email });
          }
          if (user) {
            user.facebookId = profile.id;
            user.name = profile.displayName;
            await user.save();
          } else {
            user = await User.create({
              facebookId: profile.id,
              name: profile.displayName,
              email: email,
              password: "",
            });
          }
        }
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);


app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    const token = jwt.sign(
      { userId: req.user._id, email: req.user?.email, name: req.user?.name },
      process.env.SECREAT_KEY,
      {
        expiresIn: "1h",
      }
    );
    res.redirect(`${frontendURL}?token=${token}`);
  }
);

app.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["email"] })
);

app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/" }),
  (req, res) => {
    const token = jwt.sign(
      { userId: req.user._id, email: req.user?.email, name: req.user?.name },
      process.env.SECREAT_KEY,
      {
        expiresIn: "1h",
      }
    );
    res.redirect(`${frontendURL}?token=${token}`);
  }
);

app.get("/session", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ user: req.user });
  } else {
    res.status(401).json({ error: "Not authenticated" });
  }
});

app.get("/logout", (req, res) => {
  try {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ error: "Logout failed" });
      }

      req.session.destroy((err) => {
        if (err) {
          return res.status(500).json({ error: "Session destroy failed" });
        }

        res.clearCookie("connect.sid");

        return res.status(200).json({ message: "Logged out successfully" });
      });
    });
  } catch (error) {
    res.status(500).json({ error: "Logout error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });

    if (!user)
      return res.status(400).json({ error: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ error: "Invalid email or password" });

    const token = jwt.sign({ userId: user._id }, process.env.SECREAT_KEY, {
      expiresIn: "1h",
    });

    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    res.status(500).json({ error: "Error logging in" });
  }
});

app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ ...req.body, password: hashedPassword });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error registering user" });
  }
});

app.post('/create-payment-link', async (req, res) => {
  const mockData = {
    courseId: 'course123',
    courseName: 'Introduction to Programming',
    coursePrice: 50000,
    currency: 'thb',
    returnUrl: 'payment-success',
  };

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['promptpay'],
      line_items: [
        {
          price_data: {
            currency: mockData.currency,
            product_data: {
              name: mockData.courseName,
            },
            unit_amount: mockData.coursePrice,
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: `${frontendURL}/succesful.html`,
      cancel_url: `${frontendURL}/cancellation.html`,
      metadata: {
        courseId: mockData.courseId,
      },
    });

    res.json({
      success: true,
      checkoutUrl: session.url,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, error: error.message });
  }
});

const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

module.exports = app;
