// Load environment variables from a .env file into process.env
require("dotenv").config();

// Import necessary modules
const express = require("express"); // Web framework for building APIs
const mongoose = require("mongoose"); // For interacting with MongoDB
const bcrypt = require("bcryptjs"); // For hashing passwords
const jwt = require("jsonwebtoken"); // For creating JSON Web Tokens for authentication
const passport = require("passport"); // Authentication middleware
const GoogleStrategy = require("passport-google-oauth20").Strategy; // Google OAuth strategy for Passport
const FacebookStrategy = require("passport-facebook").Strategy; // Facebook OAuth strategy for Passport
const session = require("express-session"); // To enable session support for Passport
const cors = require("cors"); // Middleware to enable Cross-Origin Resource Sharing

// Initialize Express application
const app = express();

// Middleware to parse JSON bodies from incoming requests
app.use(express.json());

// Determine the frontend URL based on the environment (development vs production)
const frontendURL =
  process.env.NODE_ENV === "production"
    ? "https://www.siam10winery.com"
    : "http://127.0.0.1:5500";

// Enable CORS with specific options: allowing the frontend URL to access this API
app.use(cors({ origin: frontendURL, credentials: true }));

// Connect to MongoDB using Mongoose with provided URI from environment variables
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch((err) => console.error("❌ MongoDB Connection Error:", err));

// ----------------------
// Define the User Schema and Model
// ----------------------
// We add both googleId and facebookId to support multiple OAuth logins.
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: String,
  address: String,
  phone: String,
  age: Number,
  gender: String,
  googleId: { type: String, unique: true, sparse: true }, // Allows null values
  facebookId: { type: String, unique: true, sparse: true }, // Allows null values
});
const User = mongoose.model("User", UserSchema);

const OrderSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    items: [
      {
        product: {
          type: mongoose.Schema.Types.ObjectId,
          ref: "Product",
          required: true,
        },
        quantity: { type: Number, required: true, min: 1 },
        price: { type: Number, required: true },
      },
    ],
    totalAmount: { type: Number, required: true },
    paymentStatus: {
      type: String,
      enum: ["pending", "paid", "failed", "refunded"],
      default: "pending",
    },
    paymentMethod: {
      type: String,
      enum: ["credit_card", "paypal", "bank_transfer"],
      required: true,
    },
    shippingAddress: {
      fullName: { type: String, required: true },
      address: { type: String, required: true },
      city: { type: String, required: true },
      postalCode: { type: String, required: true },
      country: { type: String, required: true },
    },
    status: {
      type: String,
      enum: ["processing", "shipped", "delivered", "canceled"],
      default: "processing",
    },
  },
  { timestamps: true }
);
module.exports = mongoose.model("Order", OrderSchema);

// ----------------------
// Set up Passport & Sessions
// ----------------------
// Passport requires sessions for the OAuth flow.
app.use(
  session({
    secret: process.env.SESSION_SECRET || "some secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: process.env.NODE_ENV === "production", // Secure cookies in production
      httpOnly: true, // Prevent client-side access
      sameSite: "lax", // Allow cross-origin requests with credentials
    },
  })
);

// Initialize Passport and tell it to use session support
app.use(passport.initialize());
app.use(passport.session());

// Serialize user info into the session (we use user id)
passport.serializeUser((user, done) => {
  done(null, user.id);
});

// Deserialize user info from the session by finding the user in the database
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id); // Use async/await
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// ----------------------
// Configure Google Strategy with Passport
// ----------------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID, // Your Google Client ID
      clientSecret: process.env.GOOGLE_CLIENT_SECRET, // Your Google Client Secret
      callbackURL: "/auth/google/callback", // URL to redirect back after login
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // First, try to find a user with this Google ID.
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          // If no user is found by googleId, check if a user with this email exists.
          user = await User.findOne({ email: profile.emails[0].value });
          if (user) {
            // If the user exists, update the record with googleId (if needed)
            user.googleId = profile.id;
            // Optionally update other fields like name if needed
            user.name = profile.displayName;
            await user.save();
          } else {
            // If no user exists with this email, create a new one.
            user = await User.create({
              googleId: profile.id,
              name: profile.displayName,
              email: profile.emails[0].value,
              password: "", // No password needed for OAuth logins
            });
          }
        }
        // Return the found or created user to Passport.
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

// ----------------------
// Configure Facebook Strategy with Passport
// ----------------------
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID, // Your Facebook App ID
      clientSecret: process.env.FACEBOOK_APP_SECRET, // Your Facebook App Secret
      callbackURL: "/auth/facebook/callback", // URL to redirect back after login
      profileFields: ["id", "displayName", "emails"], // Request these fields from Facebook
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await User.findOne({ facebookId: profile.id });
        if (!user) {
          // If no user is found by facebookId, try finding by email.
          const email =
            profile.emails && profile.emails[0] ? profile.emails[0].value : "";
          if (email) {
            user = await User.findOne({ email });
          }
          if (user) {
            // Update the existing user with facebookId.
            user.facebookId = profile.id;
            user.name = profile.displayName; // Optionally update name
            await user.save();
          } else {
            // Create a new user record if not found.
            user = await User.create({
              facebookId: profile.id,
              name: profile.displayName,
              email: email,
              password: "", // No password needed for OAuth logins
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

// ----------------------
// Google Auth Routes
// ----------------------

// Route to initiate Google authentication process
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google OAuth callback route
app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    // Generate a JWT token for the authenticated user
    const token = jwt.sign(
      { userId: req.user._id, email: req.user?.email, name: req.user?.name },
      process.env.SECREAT_KEY,
      {
        expiresIn: "1h",
      }
    );
    // Redirect to the frontend, passing the token as a query parameter
    res.redirect(`${frontendURL}?token=${token}`);
  }
);

// ----------------------
// Facebook Auth Routes
// ----------------------

// Route to initiate Facebook authentication process
app.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["email"] })
);

// Facebook OAuth callback route
app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/" }),
  (req, res) => {
    // Generate a JWT token for the authenticated user
    const token = jwt.sign(
      { userId: req.user._id, email: req.user?.email, name: req.user?.name },
      process.env.SECREAT_KEY,
      {
        expiresIn: "1h",
      }
    );
    // Redirect to the frontend, passing the token as a query parameter
    res.redirect(`${frontendURL}?token=${token}`);
  }
);

// ----------------------
// Existing Routes
// ----------------------

// Home route to test if our API is working
app.get("/", async (req, res) => {
  res.json("Welcome to our API!");
});

app.get("/session", (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ user: req.user });
  } else {
    res.status(401).json({ error: "Not authenticated" });
  }
});

// Logout route
app.get("/logout", (req, res) => {
  try {
    // Logout for Passport (if authenticated)
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ error: "Logout failed" });
      }

      // Destroy the session after logging out
      req.session.destroy((err) => {
        if (err) {
          return res.status(500).json({ error: "Session destroy failed" });
        }

        // Clear the session cookie to ensure it's removed from the client-side
        res.clearCookie("connect.sid"); // Use the cookie name configured by express-session

        return res.status(200).json({ message: "Logged out successfully" });
      });
    });
  } catch (error) {
    res.status(500).json({ error: "Logout error" });
  }
});

// Login route using email and password authentication
app.post("/login", async (req, res) => {
  try {
    // Get email and password from request body
    const { email, password } = req.body;
    // Find the user with the given email
    const user = await User.findOne({ email });

    // If no user is found or password does not match, return an error
    if (!user)
      return res.status(400).json({ error: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ error: "Invalid email or password" });

    // Create a JWT token with the user's ID and a 1-hour expiry
    const token = jwt.sign({ userId: user._id }, process.env.SECREAT_KEY, {
      expiresIn: "1h",
    });

    // Send back the token and basic user info to the client
    res.json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    res.status(500).json({ error: "Error logging in" });
  }
});

// Registration route to create a new user account
app.post("/register", async (req, res) => {
  try {
    // Extract email and password from request body
    const { email, password } = req.body;

    // Check if a user with this email already exists
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "Email already exists" });

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);
    // Create a new user object with the provided details and hashed password
    const newUser = new User({ ...req.body, password: hashedPassword });

    // Save the new user to the database
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ error: "Error registering user" });
  }
});

// Start the server and listen on port 5000
const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

module.exports = app;
