// Lost & Found Backend System
// Node.js + Express + PostgreSQL + JWT Authentication

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const { Pool } = require('pg');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Database Configuration
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'lost_found_db',
    password: process.env.DB_PASSWORD || 'password',
    port: process.env.DB_PORT || 5432,
});

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// File upload configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (mimetype && extname) {
            return cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'));
        }
    }
});

// Database Schema
const initDatabase = async () => {
    try {
        // Create users table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role VARCHAR(20) DEFAULT 'admin',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create lost_items table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS lost_items (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                description TEXT,
                category VARCHAR(50),
                found_location VARCHAR(255),
                collect_location VARCHAR(255),
                image_url VARCHAR(500),
                status VARCHAR(20) DEFAULT 'active',
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                collected_date TIMESTAMP NULL,
                archived_date TIMESTAMP NULL,
                added_by INTEGER REFERENCES users(id),
                collected_by VARCHAR(255) NULL,
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Create collection_history table
        await pool.query(`
            CREATE TABLE IF NOT EXISTS collection_history (
                id SERIAL PRIMARY KEY,
                item_id INTEGER REFERENCES lost_items(id) ON DELETE CASCADE,
                collected_by_name VARCHAR(255),
                collected_by_contact VARCHAR(255),
                collection_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            )
        `);

        // Create search_logs table for AI assistant
        await pool.query(`
            CREATE TABLE IF NOT EXISTS search_logs (
                id SERIAL PRIMARY KEY,
                search_query TEXT,
                results_count INTEGER,
                search_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address VARCHAR(45)
            )
        `);

        // Insert default admin user if not exists
        const adminExists = await pool.query('SELECT id FROM users WHERE username = $1', ['admin']);
        if (adminExists.rows.length === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await pool.query(
                'INSERT INTO users (email, username, password_hash, role) VALUES ($1, $2, $3, $4)',
                ['admin@college.edu', 'admin', hashedPassword, 'admin']
            );
        }

        console.log('Database initialized successfully!');
    } catch (err) {
        console.error('Database initialization error:', err);
    }
};

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        const user = await pool.query('SELECT id, username, email, role FROM users WHERE id = $1', [decoded.userId]);
        
        if (user.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid token.' });
        }

        req.user = user.rows[0];
        next();
    } catch (err) {
        res.status(403).json({ error: 'Invalid token.' });
    }
};

// Validation middleware
const validateLostItem = (req, res, next) => {
    const { name, description, found_location, collect_location } = req.body;
    
    if (!name || !description || !found_location || !collect_location) {
        return res.status(400).json({ 
            error: 'Missing required fields: name, description, found_location, collect_location' 
        });
    }
    
    if (name.length > 255 || found_location.length > 255 || collect_location.length > 255) {
        return res.status(400).json({ 
            error: 'Field length exceeds maximum allowed characters' 
        });
    }
    
    next();
};

// Routes

// Authentication Routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        
        if (user.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.rows[0].password_hash);
        
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user.rows[0].id, role: user.rows[0].role },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token: token,
            user: {
                id: user.rows[0].id,
                username: user.rows[0].username,
                email: user.rows[0].email,
                role: user.rows[0].role
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Lost Items Routes

// GET /api/lost-items - List all active lost items with filters
app.get('/api/lost-items', async (req, res) => {
    try {
        const { 
            category, 
            found_location, 
            date_from, 
            date_to, 
            sort = 'newest',
            search,
            limit = 50,
            offset = 0 
        } = req.query;

        let query = `
            SELECT li.*, u.username as added_by_username 
            FROM lost_items li 
            LEFT JOIN users u ON li.added_by = u.id 
            WHERE li.status = 'active'
        `;
        const params = [];
        let paramCount = 0;

        // Apply filters
        if (category) {
            paramCount++;
            query += ` AND li.category = $${paramCount}`;
            params.push(category);
        }

        if (found_location) {
            paramCount++;
            query += ` AND LOWER(li.found_location) LIKE LOWER($${paramCount})`;
            params.push(`%${found_location}%`);
        }

        if (search) {
            paramCount++;
            query += ` AND (LOWER(li.name) LIKE LOWER($${paramCount}) OR LOWER(li.description) LIKE LOWER($${paramCount}))`;
            params.push(`%${search}%`);
        }

        if (date_from) {
            paramCount++;
            query += ` AND li.upload_date >= $${paramCount}`;
            params.push(date_from);
        }

        if (date_to) {
            paramCount++;
            query += ` AND li.upload_date <= $${paramCount}`;
            params.push(date_to);
        }

        // Sorting
        if (sort === 'oldest') {
            query += ' ORDER BY li.upload_date ASC';
        } else {
            query += ' ORDER BY li.upload_date DESC';
        }

        // Pagination
        paramCount++;
        query += ` LIMIT $${paramCount}`;
        params.push(parseInt(limit));
        
        paramCount++;
        query += ` OFFSET $${paramCount}`;
        params.push(parseInt(offset));

        const result = await pool.query(query, params);

        // Log search query for AI assistant
        if (search) {
            await pool.query(
                'INSERT INTO search_logs (search_query, results_count, ip_address) VALUES ($1, $2, $3)',
                [search, result.rows.length, req.ip]
            );
        }

        res.json({
            items: result.rows,
            total: result.rows.length,
            filters_applied: {
                category,
                found_location,
                date_from,
                date_to,
                search,
                sort
            }
        });
    } catch (err) {
        console.error('Get lost items error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// POST /api/lost-items - Add a new lost item
app.post(
  '/api/lost-items',
  authenticateToken,
  upload.single('image'),
  validateLostItem,
  async (req, res) => {
    try {
      const { name, description, category, found_location, collect_location, notes } = req.body;
      const image_url = req.file ? `/uploads/${req.file.filename}` : null;

      const result = await pool.query(
        `INSERT INTO lost_items
        (name, description, category, found_location, collect_location, notes, image_url)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *`,
        [name, description, category, found_location, collect_location, notes, image_url]
      );

      res.status(201).json({ message: 'Lost item added successfully', item: result.rows[0] });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);
