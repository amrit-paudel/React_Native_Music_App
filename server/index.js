
// Simply importing express library
const express = require("express")

// const fetch = require('node-fetch');


// making an express server app
const app = express();


// importing cors
const cors = require("cors")

// using pool we can run queries
const pool = require('./db')

// using becrypt library to encrypt the password and get the passwordHash
const bcrypt = require('bcryptjs')

// best practice to retrive the JWT Secure Key
require('dotenv').config();

// to handle the JWT token
const jwt = require('jsonwebtoken');


// middlewares
app.use(cors())


// handy middleware 
// enables our application to automatically 
// parse JSON data  and make it available under the 
// req.body property.
app.use(express.json())




// ROUTES

// SIGN UP ROUTE
app.post("/signup", async (req, res) => {

    const { name, email, password } = req.body;

    // DEBUG
    console.log("SIGNYP DEBUG 1: Request received, req.body", req.body)

    // Basic validation (you can add more if needed)
    if (!name || !email || !password) {
        return res.status(400).json({ message: "All fields are required" });
    }

    try {
        // Check if the email already exists 
        // It contains all the rows that match the given email
        const userExists = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (userExists.rows.length > 0) {
            return res.status(409).json({ message: "Email is already registered" });
        }

        // Here you would ideally hash the password before saving (e.g., using bcrypt)
        const hashedPassword = await bcrypt.hash(password, 10);

        //   Insert user into the database
        const newUser = await pool.query(
            "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
            [name, email, hashedPassword]
        );

        // Return success response
        return res.status(201).json({
            message: "User registered successfully",
            user: {
                id: newUser.rows[0].user_id,
                name: newUser.rows[0].name,
                email: newUser.rows[0].email,
            },
        });

    } catch (error) {
        console.error(error.message);

        // Handle specific errors (e.g., unique email)
        if (error.code === '23505') { // Postgres unique violation error code
            return res.status(409).json({ message: "Email is already registered" });
        }

        // Return generic error for unexpected issues
        return res.status(500).json({ message: "Server error, please try again later" });
    }
});


// LOGIN ROUTE

const secretKey = process.env.JWT_SECRET;

console.log("JWT Secret Key", secretKey)

app.post("/login", async (req, res) => {

    const { email, password } = req.body

    // DEBUG
    console.log("LOGIN DEBUG 1: Request received, req.body", req.body)

    if (!email || !password) {
        return res.status(400).json({ message: "All fields are required" });
    }

    try {
        const user = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
        if (user.rows.length === 0) {
            return res.status(401).json({ message: "Invalid credentials" });
        }

        const storedHashedPassword = user.rows[0].password;
        const isMatch = await bcrypt.compare(password, storedHashedPassword);

        if (isMatch) {
            // Generate JWT token
            const token = jwt.sign(
                { userId: user.rows[0].id, email: user.rows[0].email }, // Payload (user data)
                process.env.JWT_SECRET, // Secret key for signing the token
                { expiresIn: '10d' } // Optional expiration
            );

            // Return token to the client
            return res.status(200).json({
                message: "Login successful",
                token: token // Sending the token
            });
        } else {
            return res.status(401).json({ message: "Invalid credentials" });
        }

    } catch (error) {
        console.error(error.message);
        return res.status(500).json({ message: "Server error, please try again later" });
    }
})


// Verify Token Endpoint
app.post('/verify-token', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1]; // Extract the token from the Authorization header

    if (!token) {
        return res.status(400).json({ isValid: false, message: 'Token is required' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ isValid: false, message: 'Invalid token' });
        }

        // Token is valid
        return res.status(200).json({ isValid: true, userId: decoded.userId, email: decoded.email });
    });
});



const redis = require('redis');
// use of redis for caching 

// Create Redis client
const redisClient = redis.createClient({
    socket: {
        host: '127.0.0.1', // Default is localhost
        port: 6379 // Default Redis port
    }
});

// Handle connection and error events
redisClient.on('connect', () => {
    console.log('Connected to Redis');
});

redisClient.on('error', (err) => {
    console.error('Redis error:', err);
});


// Connect to Redis and make sure connection is established
(async () => {
    await redisClient.connect();  // Ensure connection before performing operations
})();



// ROUTES FOR HANDLING DEEZER API

app.get('/api/music/nepalese', async (req, res) => {
    const cacheKey = 'deezer_music_data_nepalese';

    try {
        // Check if data exists in Redis cache
        const cachedData = await redisClient.get(cacheKey);

        if (cachedData) {
            // Cache hit
            console.log('Cache hit:', cacheKey);
            return res.json(JSON.parse(cachedData)); // Return cached data
        }

        // Cache miss, fetch from Deezer API
        console.log('Cache miss:', cacheKey);

        const response = await fetch('https://api.deezer.com/chart');
        const deezerData = await response.json();

        // Extract necessary data
        const musicData = deezerData.tracks.data.map(track => ({
            id: track.id,
            title: track.title,
            description: track.artist.name,
            image: track.album.cover_medium
        }));

        console.log("deezerData: ", musicData); // DEBUG

        // Store data in Redis cache with expiration time (1 hour)
        await redisClient.setEx(cacheKey, 3600, JSON.stringify(musicData));

        // Return the fresh data 
        res.json(musicData); 

    } catch (error) { 
        console.error('Error fetching or caching data:', error);
        res.status(500).json({ message: 'Internal server error' });
    } 
});


app.listen(5000, () => {
    console.log("Server has started at port: 5000")
})