const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());


//***AUTHENTICATION + AUTHORIZATION */
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

//Sample users array to represent a database
const users = [];

//Registration route
app.post('/register', async (req, res) => {
    const {username, password} = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = ({username, password: hashedPassword});
    users.push(user);
    res.status(201).json({message: 'User registered successfully'});
});

const SECRET_KEY = 'your-jwt-secret-key';

//Once users are registered, allow them to log in. On successful login, generate a JWT
app.post('/login', async (req, res) => {
    const {username, password} = req.body;

    //Find user in the 'database'
    const user = users.find(user => user.username === username);
    if (!user) return res.status(400).json({message: 'Invalid credentials'});

    //Check if passwords match
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({message: 'Invalid credentials'});

    //Generate JWT
    const token = jwt.sign({username}, SECRET_KEY, {expiresIn: '1h'});
    res.json({token});
});

//Middleware function that verifies the JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({message:'Access denied'});

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    }
    catch (error) {
        res.status(403).json({message:'Invalid token'});
    }
};



// In-memory data store for books
let books = [];

// Helper function to find book by ID
const findBookById = (id) => books.find(book => book.id === id);

// GET: Retrieve all books
app.get('/api/books', (req, res) => {
  //Only accessible to authenticated users
  res.json({books: 'Your list of books'});
});

// GET: Retrieve a book by ID
app.get('/api/books/:id', (req, res) => {
  const book = findBookById(parseInt(req.params.id));
  if (book) {
    res.json(book);
  } else {
    res.status(404).json({ message: 'Book not found' });
  }
});

// POST: Add a new book
app.post('/api/books', authenticateToken, (req, res) => {
  const { title, author, year, genre } = req.body;
  const newBook = {
    id: books.length + 1,
    title,
    author,
    year,
    genre
  };
  books.push(newBook);
  res.status(201).json(newBook);
});

// PUT: Update a book by ID
app.put('/api/books/:id', authenticateToken, (req, res) => {
  const book = findBookById(parseInt(req.params.id));
  if (book) {
    const { title, author, year, genre } = req.body;
    book.title = title || book.title;
    book.author = author || book.author;
    book.year = year || book.year;
    book.genre = genre || book.genre;
    res.json(book);
  } else {
    res.status(404).json({ message: 'Book not found' });
  }
});

// DELETE: Remove a book by ID
app.delete('/api/books/:id', authenticateToken, (req, res) => {
  const bookIndex = books.findIndex(book => book.id === parseInt(req.params.id));
  if (bookIndex !== -1) {
    const deletedBook = books.splice(bookIndex, 1);
    res.json(deletedBook[0]);
  } else {
    res.status(404).json({ message: 'Book not found' });
  }
});

app.listen(PORT, () => {
  console.log(`Library API is running on http://localhost:${PORT}`);
});
