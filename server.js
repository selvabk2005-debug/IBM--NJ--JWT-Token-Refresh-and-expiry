require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');

const app = express();
app.use(express.json());
app.use(cookieParser());

connectDB();

app.use('/api/auth', authRoutes);

app.get('/', (req, res) => res.send('IBM-NJ JWT Refresh Demo'));

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(Server running on port ${PORT}));