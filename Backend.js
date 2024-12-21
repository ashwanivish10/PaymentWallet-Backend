const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Initialize Express app
const app = express();

// Middleware setup
app.use(cors());
app.use(bodyParser.json());
app.use(express.json());

// MongoDB Connection
mongoose.connect('mongodb+srv://your_username:your_password@cluster0.mongodb.net/payment_wallet', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  upiId: { type: String, unique: true },
  balance: { type: Number, default: 1000 }
});

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  sender_upi_id: { type: String, required: true },
  receiver_upi_id: { type: String, required: true },
  amount: { type: Number, required: true },
  timestamp: { type: Date, default: Date.now }
});

// Models
const User = mongoose.model('User', userSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);

// Generate UPI ID
function generateUPI() {
  return crypto.randomBytes(12).toString('hex');
}

// JWT Secret
const JWT_SECRET = 'your-secret-key';

// Signup Route
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate UPI ID
    const upiId = generateUPI();

    // Create new user
    const user = new User({
      name,
      email,
      password: hashedPassword,
      upiId,
      balance: 1000 // Initial balance
    });

    await user.save();

    res.status(201).json({
      message: 'User created successfully',
      upiId,
      name,
      email
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

// Login Route
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(400).json({ message: 'Invalid password' });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      message: 'Login successful',
      token,
      upiId: user.upiId,
      balance: user.balance
    });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
});

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Transaction Route
app.post('/api/transaction', authenticateToken, async (req, res) => {
  try {
    const { sender_upi_id, receiver_upi_id, amount } = req.body;

    // Find sender and receiver
    const sender = await User.findOne({ upiId: sender_upi_id });
    const receiver = await User.findOne({ upiId: receiver_upi_id });

    if (!sender || !receiver) {
      return res.status(400).json({ message: 'Invalid UPI IDs' });
    }

    // Check balance
    if (sender.balance < amount) {
      return res.status(400).json({ message: 'Insufficient balance' });
    }

    // Create transaction
    const transaction = new Transaction({
      sender_upi_id,
      receiver_upi_id,
      amount
    });

    // Update balances
    sender.balance -= amount;
    receiver.balance += amount;

    await Promise.all([
      transaction.save(),
      sender.save(),
      receiver.save()
    ]);

    res.json({
      message: 'Transaction successful',
      transaction,
      newBalance: sender.balance
    });
  } catch (error) {
    res.status(500).json({ message: 'Error processing transaction', error: error.message });
  }
});

// Get Balance Route
app.get('/api/balance', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    res.json({ balance: user.balance });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching balance', error: error.message });
  }
});

// Get Transaction History
app.get('/api/transactions', authenticateToken, async (req, res) => {
  try {
    const user = await User.findOne({ email: req.user.email });
    const transactions = await Transaction.find({
      $or: [
        { sender_upi_id: user.upiId },
        { receiver_upi_id: user.upiId }
      ]
    }).sort({ timestamp: -1 });

    res.json({ transactions });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching transactions', error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});