// server.js
import express from 'express';// import express
import mongoose from 'mongoose'; // import mongoose
import http from 'http';// http request
import { Server } from 'socket.io';// web socket
import ChatMessage from './models/message.js';// database models
import jwt from 'jsonwebtoken';// web token for authentication
import bcrypt from 'bcrypt';//bcrypt
import dotenv from 'dotenv';//enviournmanet variable
import User from './models/user.js';// model for aithentication
dotenv.config();// enviornment variable

// Initialize Express
const app = express();
const server = http.createServer(app);
const io = new Server(server);

// Middleware to parse JSON and serve static files
app.use(express.json());
app.use(express.static('public'));// from here we integrate frontend and backend

// MongoDB connection using Mongoose
const mongoURI = 'mongodb+srv://ayush2211:rdEpYcbOSLYS0TKb@cluster1.2qupd.mongodb.net/';// mongodb 
mongoose.connect(mongoURI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';// jwt token

// Middleware to authenticate JWT tokens
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];// if check for token
    const token = authHeader && authHeader.split(' ')[1];// exact the token
    if (!token) return res.status(401).json({ error: 'Access token required' });// if no token 

    jwt.verify(token, JWT_SECRET, (err, user) => {// verify the token
        if (err) return res.status(403).json({ error: 'Invalid token' });// if invalid token
        req.user = user; // Attach user info from token to request
        next();// proceed next
    });
}

// POST request for user registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);// it safely store in database

        // Create new user
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        console.log(`User registered: ${username}`); // Log successful registration
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Error during registration:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// POST request for user login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        // Find user by username
        const user = await User.findOne({ username });
        if (!user) {
            console.log(`User not found: ${username}`);
            return res.status(404).json({ error: 'User not found' });
        }

        // Compare password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            console.log(`Invalid password attempt for user: ${username}`);
            return res.status(401).json({ error: 'Invalid password' });
        }

        // Generate JWT token
        const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        console.log(`User logged in: ${username}`); // Log successful login
        res.json({ token, username: user.username }); // Send token and username back
    } catch (err) {
        console.error('Error during login:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// GET request to check login status
app.get('/status', authenticateToken, (req, res) => {
    res.json({ loggedIn: true, user: req.user });
});

// GET request to load all previously sent messages
app.get('/messages', async (req, res) => {
    try {
        const messages = await ChatMessage.find().sort({ timestamp: 1 });
        res.json(messages);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// POST request to send a new message
app.post('/messages', authenticateToken, async (req, res) => {
    try {
        const { message } = req.body;
        const user = req.user.username; // Get username from the authenticated token

        if (!message) {
            return res.status(400).json({ error: 'Message is required' });
        }

        const chatMessage = new ChatMessage({ user, message });
        await chatMessage.save();

        io.emit('newMessage', chatMessage); // Emit the new message to all clients

        res.status(201).json(chatMessage); // Respond with the saved message
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// DELETE request to delete a message
app.delete('/messages/:id', async (req, res) => {
    const messageId = req.params.id;
    try {
        const deletedMessage = await ChatMessage.findByIdAndDelete(messageId);

        if (!deletedMessage) {
            return res.status(404).json({ error: 'Message not found' });
        }

        res.sendStatus(200);
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Socket.IO setup
io.on('connection', (socket) => {
    console.log('A user connected');

    socket.on('fetchMessages', async () => {
        try {
            const messages = await ChatMessage.find().sort({ timestamp: 1 });
            socket.emit('loadMessages', messages);
        } catch (error) {
            console.error('Error fetching messages:', error);
        }
    });

    socket.on('disconnect', () => {
        console.log('A user disconnected');
    });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
