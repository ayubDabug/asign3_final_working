require('dotenv').config();
const express = require('express');
const app = express();
const cors = require('cors');
const mongoose = require('mongoose');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');

// --- PASSPORT JWT SETUP ---
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme("jwt"),
    secretOrKey: process.env.JWT_SECRET
};

const strategy = new JwtStrategy(jwtOptions, function (jwt_payload, next) {
    if (jwt_payload) {
        // Only including _id and userName as required by assignment spec
        next(null, {
            _id: jwt_payload._id,
            userName: jwt_payload.userName,
        });
    } else {
        next(null, false);
    }
});

passport.use(strategy);


// --- MIDDLEWARE & DATABASE ---
app.use(passport.initialize());
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URL)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));


// --- USER MODEL DEFINITION ---
const { Schema } = mongoose;

const userSchema = new Schema({
    userName: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    favourites: [{ type: String }] // Array of book IDs
});

const UserModel = mongoose.model("users", userSchema);


// --- ROUTES ---

// UNPROTECTED ROUTE: Registration
// Corresponds to POST /api/user/register from the frontend
app.post("/register", (req, res) => {
    const { userName, password } = req.body;
    
    const newUser = new UserModel({ userName, password });
    newUser.save()
        .then(user => {
            // Assignment specifies no token on successful registration
            res.json({ message: "User created successfully", user: { _id: user._id, userName: user.userName } });
        })
        .catch(err => {
            if (err.code === 11000) {
                return res.status(409).json({ message: "Error creating user: Username already taken." });
            }
            res.status(422).json({ message: "Error creating user: " + err });
        });
});

// UNPROTECTED ROUTE: Login (Returns JWT)
// Corresponds to POST /api/user/login from the frontend
app.post("/login", (req, res) => {
    UserModel.findOne({ userName: req.body.userName })
        .then(user => {
            if (user && user.password === req.body.password) {
                // Generate payload with _id and userName properties
                const payload = {
                    _id: user._id,
                    userName: user.userName
                };
                
                // Sign token using JWT_SECRET
                const token = jwt.sign(payload, process.env.JWT_SECRET);
                
                // Include token in the JSON response
                res.json({ message: "login successful", token: token });
            } else {
                res.status(401).json({ message: "Incorrect credentials" });
            }
        })
        .catch(err => {
            res.status(422).json({ message: "Error logging in: " + err });
        });
});

// PROTECTED ROUTE: GET /api/user/favourites
app.get("/favourites", passport.authenticate('jwt', { session: false }), (req, res) => {
    UserModel.findOne({ _id: req.user._id })
        .then(user => {
            res.json(user.favourites);
        })
        .catch(err => {
            res.status(500).json({ message: "Error fetching favourites" });
        });
});

// PROTECTED ROUTE: PUT /api/user/favourites/:id
app.put("/favourites/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    UserModel.updateOne(
        { _id: req.user._id },
        { $addToSet: { favourites: req.params.id } }
    )
        .then(() => UserModel.findOne({ _id: req.user._id }))
        .then(user => {
            res.json(user.favourites);
        })
        .catch(err => {
            res.status(500).json({ message: "Error adding to favourites" });
        });
});

// PROTECTED ROUTE: DELETE /api/user/favourites/:id
app.delete("/favourites/:id", passport.authenticate('jwt', { session: false }), (req, res) => {
    UserModel.updateOne(
        { _id: req.user._id },
        { $pull: { favourites: req.params.id } }
    )
        .then(() => UserModel.findOne({ _id: req.user._id }))
        .then(user => {
            res.json(user.favourites);
        })
        .catch(err => {
            res.status(500).json({ message: "Error removing from favourites" });
        });
});

// Default root route to confirm API is online
app.get("/", (req, res) => {
    res.json({ message: "User API is ONLINE" });
});


// FINAL STEP: Export the Express app for Vercel Serverless deployment
module.exports = app;
