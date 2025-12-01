const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const archiver = require('archiver');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

dotenv.config();

const app = express();

// Security Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.CORS_ORIGIN || '*',
  credentials: true
}));

// Rate Limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests'
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many login attempts'
});

app.use('/api/', limiter);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/billboard-tracking', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('✅ MongoDB Connected');
}).catch(err => {
  console.error('❌ MongoDB Error:', err.message);
  process.exit(1);
});

// Schemas
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['admin', 'photographer', 'client'], required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: Date
});

const billboardSchema = new mongoose.Schema({
  name: { type: String, required: true },
  location: { type: String, required: true },
  assignedClient: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const pictureSchema = new mongoose.Schema({
  filename: String,
  filepath: String,
  billboardId: { type: mongoose.Schema.Types.ObjectId, ref: 'Billboard', required: true },
  photographerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  clientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  gps: {
    latitude: Number,
    longitude: Number
  },
  timestamp: { type: Date, default: Date.now },
  comment: String,
  uploadedAt: { type: Date, default: Date.now }
});

const activityLogSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  action: String,
  details: String,
  timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Billboard = mongoose.model('Billboard', billboardSchema);
const Picture = mongoose.model('Picture', pictureSchema);
const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// Helper Functions
const hashPassword = async (password) => bcryptjs.hash(password, 10);
const comparePassword = async (password, hash) => bcryptjs.compare(password, hash);

const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
};

const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET || 'secret');
  } catch (error) {
    return null;
  }
};

const logActivity = async (userId, action, details) => {
  try {
    await ActivityLog.create({ userId, action, details });
  } catch (error) {
    console.error('Activity log error:', error);
  }
};

// Middleware
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });

    const decoded = verifyToken(token);
    if (!decoded) return res.status(401).json({ error: 'Invalid token' });

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(401).json({ error: 'User not found' });

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Auth failed' });
  }
};

const adminOnly = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// File Upload Setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = process.env.FILE_UPLOAD_PATH || './uploads';
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: parseInt(process.env.MAX_FILE_SIZE) || 10485760 }
});

// Routes

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'Backend is running!' });
});

// AUTH Routes
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const validPassword = await comparePassword(password, user.password);
    if (!validPassword) return res.status(401).json({ error: 'Invalid credentials' });

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    await logActivity(user._id, 'LOGIN', `User logged in`);

    const token = generateToken(user._id);
    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ADMIN Routes
app.get('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const users = await User.find({}, '-password');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/users', auth, adminOnly, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'Email already exists' });

    const hashedPassword = await hashPassword(password);
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role
    });

    await logActivity(req.user._id, 'CREATE_USER', `Created user: ${email}`);

    res.status(201).json({
      message: 'User created',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const updateData = { name, email, role };

    if (password) {
      updateData.password = await hashPassword(password);
    }

    const user = await User.findByIdAndUpdate(req.params.id, updateData, { new: true });
    await logActivity(req.user._id, 'UPDATE_USER', `Updated user: ${email}`);

    res.json({ message: 'User updated', user });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/users/:id', auth, adminOnly, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    await User.findByIdAndDelete(req.params.id);

    await logActivity(req.user._id, 'DELETE_USER', `Deleted user: ${user.email}`);

    res.json({ message: 'User deleted' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// BILLBOARD Routes
app.get('/api/admin/billboards', auth, adminOnly, async (req, res) => {
  try {
    const billboards = await Billboard.find().populate('assignedClient', 'name email');
    const billboardsWithPictures = await Promise.all(
      billboards.map(async (billboard) => {
        const pictureCount = await Picture.countDocuments({ billboardId: billboard._id });
        return {
          ...billboard.toObject(),
          pictures: pictureCount
        };
      })
    );
    res.json(billboardsWithPictures);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/billboards', auth, adminOnly, async (req, res) => {
  try {
    const { name, location } = req.body;
    const billboard = await Billboard.create({ name, location });

    await logActivity(req.user._id, 'CREATE_BILLBOARD', `Created billboard: ${name}`);

    res.status(201).json({ message: 'Billboard created', billboard });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/billboards/:id/assign', auth, adminOnly, async (req, res) => {
  try {
    const { clientId } = req.body;
    const billboard = await Billboard.findByIdAndUpdate(
      req.params.id,
      { assignedClient: clientId },
      { new: true }
    );

    await logActivity(req.user._id, 'ASSIGN_BILLBOARD', `Assigned billboard to client`);

    res.json({ message: 'Billboard assigned', billboard });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/admin/billboards/:id/unassign', auth, adminOnly, async (req, res) => {
  try {
    const billboardId = req.params.id;
    const pictures = await Picture.find({ billboardId });

    // Create ZIP file
    const archive = archiver('zip', { zlib: { level: 9 } });
    const output = fs.createWriteStream(`./unassign-${billboardId}.zip`);

    archive.pipe(output);

    // Add pictures to ZIP
    pictures.forEach(pic => {
      if (fs.existsSync(pic.filepath)) {
        archive.file(pic.filepath, { name: pic.filename });
      }
    });

    await archive.finalize();

    // Wait for ZIP to finish
    await new Promise((resolve) => output.on('close', resolve));

    // Delete pictures from database and filesystem
    await Promise.all(pictures.map(async (pic) => {
      if (fs.existsSync(pic.filepath)) {
        fs.unlinkSync(pic.filepath);
      }
      await Picture.findByIdAndDelete(pic._id);
    }));

    // Unassign billboard
    const billboard = await Billboard.findByIdAndUpdate(
      billboardId,
      { assignedClient: null },
      { new: true }
    );

    await logActivity(req.user._id, 'UNASSIGN_BILLBOARD', `Unassigned billboard: ${pictures.length} pictures deleted`);

    // Send ZIP file
    res.download(`./unassign-${billboardId}.zip`, () => {
      fs.unlinkSync(`./unassign-${billboardId}.zip`);
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PHOTOGRAPHER Routes
app.get('/api/photographer/billboards', auth, async (req, res) => {
  try {
    const billboards = await Billboard.find();
    res.json(billboards);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/photographer/upload', auth, upload.single('picture'), async (req, res) => {
  try {
    const { billboardId, comment, latitude, longitude } = req.body;

    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const billboard = await Billboard.findById(billboardId);
    if (!billboard) return res.status(404).json({ error: 'Billboard not found' });

    const picture = await Picture.create({
      filename: req.file.filename,
      filepath: req.file.path,
      billboardId,
      photographerId: req.user._id,
      clientId: billboard.assignedClient,
      gps: {
        latitude: parseFloat(latitude) || 0,
        longitude: parseFloat(longitude) || 0
      },
      comment
    });

    await logActivity(req.user._id, 'UPLOAD_PICTURE', `Uploaded picture to billboard: ${billboard.name}`);

    res.status(201).json({ message: 'Picture uploaded', picture });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/photographer/my-pictures', auth, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const pictures = await Picture.find({
      photographerId: req.user._id,
      uploadedAt: { $gte: today }
    }).populate('billboardId', 'name location');

    res.json(pictures);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// CLIENT Routes
app.get('/api/client/billboards', auth, async (req, res) => {
  try {
    const billboards = await Billboard.find({ assignedClient: req.user._id });
    res.json(billboards);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/client/pictures', auth, async (req, res) => {
  try {
    const billboards = await Billboard.find({ assignedClient: req.user._id });
    const billboardIds = billboards.map(b => b._id);

    const pictures = await Picture.find({ billboardId: { $in: billboardIds } })
      .populate('billboardId', 'name location')
      .populate('photographerId', 'name');

    res.json(pictures);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ADMIN Dashboard
app.get('/api/admin/dashboard', auth, adminOnly, async (req, res) => {
  try {
    const totalBillboards = await Billboard.countDocuments();
    const assignedBillboards = await Billboard.countDocuments({ assignedClient: { $ne: null } });
    const totalPictures = await Picture.countDocuments();
    const totalUsers = await User.countDocuments();

    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const uploadsToday = await Picture.countDocuments({ uploadedAt: { $gte: today } });

    const recentActivity = await ActivityLog.find()
      .populate('userId', 'name email')
      .sort({ timestamp: -1 })
      .limit(10);

    res.json({
      stats: {
        totalBillboards,
        assignedBillboards,
        unassignedBillboards: totalBillboards - assignedBillboards,
        totalPictures,
        totalUsers,
        uploadsToday
      },
      recentActivity
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Error Handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
});
