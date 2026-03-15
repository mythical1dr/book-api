const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

/* ======================
   DATABASE (POSTGRES)
====================== */
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST,       // <-- Terraform-generated RDS endpoint
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
  ssl: false                        // RDS inside VPC
});

// Simple startup check
pool.query('SELECT 1')
  .then(() => console.log('Connected to RDS'))
  .catch(err => {
    console.error('DB connection failed', err);
    process.exit(1);
  });

/* ======================
   AUTH
====================== */
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const SECRET_KEY = process.env.JWT_SECRET || 'dev-secret';

/* ======================
   USERS
====================== */

// Registration
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2)',
      [username, hashedPassword]
    );
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const result = await pool.query(
    'SELECT * FROM users WHERE username = $1',
    [username]
  );

  if (result.rows.length === 0) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const user = result.rows[0];
  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(400).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

/* ======================
   AUTH MIDDLEWARE
====================== */
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Access denied' });

  try {
    req.user = jwt.verify(token, SECRET_KEY);
    next();
  } catch {
    res.status(403).json({ message: 'Invalid token' });
  }
};

/* ======================
   BOOKS
====================== */

// GET all books
app.get('/api/books', authenticateToken, async (req, res) => {
  const result = await pool.query('SELECT * FROM books ORDER BY id');
  res.json(result.rows);
});

// GET book by ID
app.get('/api/books/:id', authenticateToken, async (req, res) => {
  const result = await pool.query(
    'SELECT * FROM books WHERE id = $1',
    [req.params.id]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ message: 'Book not found' });
  }

  res.json(result.rows[0]);
});

// POST book
app.post('/api/books', authenticateToken, async (req, res) => {
  const { title, author, year, genre } = req.body;

  const result = await pool.query(
    `INSERT INTO books (title, author, year, genre)
     VALUES ($1, $2, $3, $4)
     RETURNING *`,
    [title, author, year, genre]
  );

  res.status(201).json(result.rows[0]);
});

// PUT book
app.put('/api/books/:id', authenticateToken, async (req, res) => {
  const { title, author, year, genre } = req.body;

  const result = await pool.query(
    `UPDATE books
     SET title = COALESCE($1, title),
         author = COALESCE($2, author),
         year = COALESCE($3, year),
         genre = COALESCE($4, genre)
     WHERE id = $5
     RETURNING *`,
    [title, author, year, genre, req.params.id]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ message: 'Book not found' });
  }

  res.json(result.rows[0]);
});

// DELETE book
app.delete('/api/books/:id', authenticateToken, async (req, res) => {
  const result = await pool.query(
    'DELETE FROM books WHERE id = $1 RETURNING *',
    [req.params.id]
  );

  if (result.rows.length === 0) {
    return res.status(404).json({ message: 'Book not found' });
  }

  res.json(result.rows[0]);
});

/* ======================
   START
====================== */
app.listen(PORT, () => {
  console.log(`Library API running on port ${PORT}`);
});
