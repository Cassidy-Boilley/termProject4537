const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { body, validationResult } = require('express-validator');
const fetch = require('node-fetch');

const app = express();
const port = 3000;

const { messages } = require('./messages.js');

// Connect to MongoDB using the provided connection string
mongoose.connect(process.env.MONGODB_CONNECTIONSTRING, {
    dbName: process.env.MONGODB_DBNAME
});

// Define MongoDB schemas and models using Mongoose
const rolesSchema = new mongoose.Schema({
  title: String,
  role_id: Number
});

const usersSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  email: { type: String, unique: true },
  password: String,
  role_id: Number
});

const apiCallsSchema = new mongoose.Schema({
  user_name: String,
  call_count: Number
});

const Role = mongoose.model('Role', rolesSchema);
const User = mongoose.model('User', usersSchema);
const ApiCall = mongoose.model('ApiCall', apiCallsSchema);

const corsOptions = {
  origin: 'https://cassidyboilley-labs.netlify.app/', // Update with the origin of your client-side code
  credentials: true // Enable credentials
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(cookieParser());

// Route for user registration
app.post('/register', async (req, res) => {
    try {
        
      const { username, email, password } = req.body;
      
      const emailSchema = Joi.string().max(20).required();
      const usernameSchema = Joi.string().max(20).required();
      const passwordSchema = Joi.string().max(20).required();
      const emailValidationResult = emailSchema.validate(email);
      const usernameValidationResult = usernameSchema.validate(username);
      const passwordValidationResult = passwordSchema.validate(password);

  if (emailValidationResult.error != null || passwordValidationResult.error != null || usernameValidationResult.error != null) {  
    console.log(emailValidationResult.error);
    console.log(passwordValidationResult.error);
    console.log(usernameValidationResult.error);
    res.send("<h1 style='color:darkred;'>Alert - NoSQL injection attack was detected. </h1>");
    return;
 }	
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
    try {
        
      const { username, email, password } = req.body;
      
      const emailSchema = Joi.string().max(20).required();
      const usernameSchema = Joi.string().max(20).required();
      const passwordSchema = Joi.string().max(20).required();
      const emailValidationResult = emailSchema.validate(email);
      const usernameValidationResult = usernameSchema.validate(username);
      const passwordValidationResult = passwordSchema.validate(password);

  if (emailValidationResult.error != null || passwordValidationResult.error != null || usernameValidationResult.error != null) {  
    console.log(emailValidationResult.error);
    console.log(passwordValidationResult.error);
    console.log(usernameValidationResult.error);
    res.send("<h1 style='color:darkred;'>Alert - NoSQL injection attack was detected. </h1>");
    return;
 }	
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save the user to the database with the hashed password
        const user = new User({ username, email, password: hashedPassword, role_id: 1 });
        const apiUser = new ApiCall({ user_name: username, call_count: 0 });
        // Save the user to the database with the hashed password
        const user = new User({ username, email, password: hashedPassword, role_id: 1 });
        const apiUser = new ApiCall({ user_name: username, call_count: 0 });

        await user.save();
        await apiUser.save();
        res.status(201).json({ message: "User registered successfully"});
    } catch (error) {
        console.error("Error registering user: " + error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});
// Route to handle user login
// Route to handle user login
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
    try {
        const { username, password } = req.body;

        // Fetch the user from the database
        const user = await User.findOne({ username });
        // Fetch the user from the database
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }

        // Compare passwords
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            // Fetch role from MongoDB
            const userRole = user.role_id === 1 ? 'user' : 'admin';

            // Generate JWT token with user data
            const token = jwt.sign({ username, role: userRole }, process.env.JWT_SECRET, { expiresIn: '1h' });

            res.cookie('token', token, { httpOnly: true, maxAge: 3600000 }); // Max age 1 hour

            res.status(200).json({ message: 'Login successful', role: userRole, token }); // Include token in response
        } else {
            res.status(401).json({ error: 'Invalid username or password' });
        }
    } catch (error) {
        console.error("Error logging in: " + error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
        // Compare passwords
        const match = await bcrypt.compare(password, user.password);
        if (match) {
            // Fetch role from MongoDB
            const userRole = user.role_id === 1 ? 'user' : 'admin';

            // Generate JWT token with user data
            const token = jwt.sign({ username, role: userRole }, process.env.JWT_SECRET, { expiresIn: '1h' });

            res.cookie('token', token, { httpOnly: true, maxAge: 3600000 }); // Max age 1 hour

            res.status(200).json({ message: 'Login successful', role: userRole, token }); // Include token in response
        } else {
            res.status(401).json({ error: 'Invalid username or password' });
        }
    } catch (error) {
        console.error("Error logging in: " + error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Route to check if a username or email already exists
app.get('/checkuser', async (req, res) => {
  const { username, email } = req.query;
  
  try {
    const existingUser = await User.findOne({ $or: [{ username }, { email }] });
    res.status(200).json({ usernameUnique: !existingUser, emailUnique: !existingUser });
  } catch (error) {
    console.error("Error checking username and email: " + error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
// Route to get user information including API call count
app.get('/users', async (req, res) => {
  try {
    
    const authHeader = req.headers['authorization']; 
    
    const authHeader = req.headers['authorization']; 
    // Retrieve user information from the database

    const token = authHeader.split(' ')[1]; // Extract the token from the Authorization header

    if(jwt.verify(token, process.env.JWT_SECRET).role == 'admin') {


    const token = authHeader.split(' ')[1]; // Extract the token from the Authorization header

    if(jwt.verify(token, process.env.JWT_SECRET).role == 'admin') {

    const users = await User.find({}, { password: 0 });

      // Fetch API call count for each user
      const usersWithApiCalls = await Promise.all(users.map(async user => {
      // Find the corresponding API call record for the user
        const apiCall = await ApiCall.findOne({ user_name: user.username });

        // If API call record found, get the call count, otherwise set it to 0
        const apiCallCount = apiCall ? apiCall.call_count : 0;

        // Convert Mongoose document to plain JavaScript object
        const userData = user.toObject();
          
        // Add API call count to user object
        userData.api_call_count = apiCallCount;

        return userData;
      }));
        const apiCall = await ApiCall.findOne({ user_name: user.username });

        // If API call record found, get the call count, otherwise set it to 0
        const apiCallCount = apiCall ? apiCall.call_count : 0;

        // Convert Mongoose document to plain JavaScript object
        const userData = user.toObject();
          
        // Add API call count to user object
        userData.api_call_count = apiCallCount;

        return userData;
      }));

      res.status(200).json({ users: usersWithApiCalls });
    }
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/api-call', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader.split(' ')[1];
    const userType = jwt.verify(token, process.env.JWT_SECRET).role;
    
    if (['user', 'admin'].includes(userType)) {
      const username = jwt.verify(token, process.env.JWT_SECRET).username;

      // Update the call count for the current user
      await ApiCall.findOneAndUpdate(
        { user_name: username },
        { $inc: { call_count: 1 } },
        { new: true } // Make sure to return the updated document
      );

      // Find the user's API call count
      const apiCount = await ApiCall.findOne({ user_name: username });


      const { text } = req.body; // Extract the text from the request body

      // Send a POST request to the external API with the given text
      const response = await fetch('https://comp4537labs.com/project/answer', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ text })
      });

      // Check if the response is successful
      if (response.ok) {
        const responseData = await response.json();
        
        // Add the API call count to the response data
        responseData.apiCount = apiCount ? apiCount.call_count : 0;
        
        console.log(responseData);
        res.status(200).json(responseData); // Send the response data back to the client
      } else {
        res.status(500).json({ error: 'Failed to fetch data from the external API' });
      }
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.post('/api-call', async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader.split(' ')[1];
    const userType = jwt.verify(token, process.env.JWT_SECRET).role;
    
    if (['user', 'admin'].includes(userType)) {
      const username = jwt.verify(token, process.env.JWT_SECRET).username;

      // Update the call count for the current user
      await ApiCall.findOneAndUpdate(
        { user_name: username },
        { $inc: { call_count: 1 } },
        { new: true } // Make sure to return the updated document
      );

      // Find the user's API call count
      const apiCount = await ApiCall.findOne({ user_name: username });


      const { text } = req.body; // Extract the text from the request body

      // Send a POST request to the external API with the given text
      const response = await fetch('https://comp4537labs.com/project/answer', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ text })
      });

      // Check if the response is successful
      if (response.ok) {
        const responseData = await response.json();
        
        // Add the API call count to the response data
        responseData.apiCount = apiCount ? apiCount.call_count : 0;
        
        console.log(responseData);
        res.status(200).json(responseData); // Send the response data back to the client
      } else {
        res.status(500).json({ error: 'Failed to fetch data from the external API' });
      }
    }
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});