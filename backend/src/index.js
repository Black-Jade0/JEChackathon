const express = require('express');
const cors = require('cors');

const authMiddleware = require('./authMiddleware');

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
const allowedOrigins = ['http://localhost:5173'];

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  }
};
app.use(cors(corsOptions));

app.use(express.json());

// // Routes
app.use('/api/auth', require('./routes/auth'));
// app.use('/api/admin', authMiddleware(['ADMIN']),require('./routes/admin'));
// app.use('/api/user', authMiddleware(['USER', 'ADMIN']), require('./routes/user'));



// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Server is running' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});