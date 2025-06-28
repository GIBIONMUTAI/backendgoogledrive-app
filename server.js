require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');

const app = express();

// Middleware
app.use(cors());
app.use(express.json()); // For parsing application/json

// Connect to MongoDB
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URI);
        console.log('MongoDB Connected...');
    } catch (err) {
        console.error(err.message);
        process.exit(1);
    }
};

connectDB();

// Define Schemas and Models
// models/User.js
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', UserSchema);

// models/Folder.js
const FolderSchema = new mongoose.Schema({
    name: { type: String, required: true },
    parent: { type: mongoose.Schema.Types.ObjectId, ref: 'Folder', default: null },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
});
const Folder = mongoose.model('Folder', FolderSchema);

// models/File.js
const FileSchema = new mongoose.Schema({
    name: { type: String, required: true },
    url: { type: String, required: true }, // URL from cloud storage (e.g., Cloudinary, S3)
    mimetype: { type: String, required: true },
    size: { type: Number, required: true }, // Size in bytes
    folder: { type: mongoose.Schema.Types.ObjectId, ref: 'Folder', default: null },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    createdAt: { type: Date, default: Date.now }
});
const File = mongoose.model('File', FileSchema);

// Auth Middleware
// middleware/auth.js
const jwt = require('jsonwebtoken');

const auth = (req, res, next) => {
    // Get token from header
    const token = req.header('x-auth-token');

    // Check if not token
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    // Verify token
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded.user; // decoded.user will contain { id: userId }
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// Routes
const bcrypt = require('bcryptjs');

// routes/auth.js
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        // Check if user exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        user = new User({ username, email, password });

        // Hash password
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        await user.save();

        // Return JWT
        const payload = {
            user: {
                id: user.id
            }
        };

        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '5h' },
            (err, token) => {
                if (err) throw err;
                res.json({ token });
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Credentials' });
        }

        const payload = {
            user: {
                id: user.id
            }
        };

        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '5h' },
            (err, token) => {
                if (err) throw err;
                res.json({ token });
            }
        );

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.get('/api/auth/me', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password'); // Exclude password
        res.json(user);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// routes/folders.js
app.post('/api/folders', auth, async (req, res) => {
    const { name, parentId } = req.body; // parentId can be null for root folders

    try {
        const newFolder = new Folder({
            name,
            parent: parentId || null,
            owner: req.user.id
        });

        const folder = await newFolder.save();
        res.json(folder);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.get('/api/folders', auth, async (req, res) => {
    const { parentId } = req.query; // Get files/folders inside a specific parentId, or null for root

    try {
        const folders = await Folder.find({ owner: req.user.id, parent: parentId || null });
        const files = await File.find({ owner: req.user.id, folder: parentId || null });

        res.json({ folders, files });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.put('/api/folders/:id', auth, async (req, res) => {
    const { name } = req.body;

    try {
        let folder = await Folder.findOne({ _id: req.params.id, owner: req.user.id });
        if (!folder) {
            return res.status(404).json({ msg: 'Folder not found or not authorized' });
        }

        folder.name = name;
        await folder.save();
        res.json(folder);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.delete('/api/folders/:id', auth, async (req, res) => {
    try {
        let folder = await Folder.findOne({ _id: req.params.id, owner: req.user.id });
        if (!folder) {
            return res.status(404).json({ msg: 'Folder not found or not authorized' });
        }

        // Optional: Recursively delete subfolders and files
        // For simplicity, this example just deletes the folder.
        // In a real app, you'd want to handle children deletion carefully.
        await Folder.deleteMany({ parent: req.params.id, owner: req.user.id });
        await File.deleteMany({ folder: req.params.id, owner: req.user.id });

        await folder.deleteOne();
        res.json({ msg: 'Folder and its contents deleted' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// routes/files.js
const multer = require('multer');
const upload = multer({ dest: 'uploads/' }); // Temporary storage for multer

// In a real application, you would integrate with a cloud storage service here (e.g., Cloudinary, AWS S3).
// This is a simplified example that just saves metadata and simulates a URL.
app.post('/api/files/upload', auth, upload.single('file'), async (req, res) => {
    const { folderId } = req.body;
    const { originalname, mimetype, size, path: tempFilePath } = req.file;

    try {
        // Simulate upload to a cloud service and get a URL
        // In a real app, 'fileUrl' would come from Cloudinary/S3 after upload
        const fileUrl = `http://example.com/uploads/${req.file.filename}`; // Placeholder URL

        const newFile = new File({
            name: originalname,
            url: fileUrl,
            mimetype,
            size,
            folder: folderId || null,
            owner: req.user.id
        });

        const file = await newFile.save();
        // Clean up temp file (after actual cloud upload)
        // fs.unlink(tempFilePath, (err) => { if (err) console.error("Error deleting temp file:", err); });
        res.json(file);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.put('/api/files/:id', auth, async (req, res) => {
    const { name } = req.body;

    try {
        let file = await File.findOne({ _id: req.params.id, owner: req.user.id });
        if (!file) {
            return res.status(404).json({ msg: 'File not found or not authorized' });
        }

        file.name = name;
        await file.save();
        res.json(file);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.delete('/api/files/:id', auth, async (req, res) => {
    try {
        let file = await File.findOne({ _id: req.params.id, owner: req.user.id });
        if (!file) {
            return res.status(404).json({ msg: 'File not found or not authorized' });
        }

        // In a real app, you would also delete the file from the cloud storage service here.
        await file.deleteOne();
        res.json({ msg: 'File deleted' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});


// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
