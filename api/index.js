const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const cors = require('cors');
require('dotenv').config();

const app = express();
const port = 3000;

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

app.use(cors());
app.use(express.json());

const corsOptions = {
  origin: 'https://cassidyboilley-labs.netlify.app/comp4537/termproject', // Update with the origin of your client-side code
  credentials: true // Enable credentials
  
};
app.use(cors(corsOptions));

// Route for user registration
// Route for user registration
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Check if username, email, and password are provided
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save the user to the database with the hashed password
    const user = new User({ username, email, password: hashedPassword, role_id: 1 });
    const apiUser = new ApiCall({ user_name: username, call_count: 0 });

    await user.save();
    await apiUser.save();

    console.log("User registered successfully");
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error("Error registering user: " + error.message);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// Route for user login
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Fetch the user from the database
    const user = await User.findOne({ username });

    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Compare passwords
    const match = await bcrypt.compare(password, user.password);
    if (match) {
      // Check the role of the user
      const role = user.role_id === 1 ? 'user' : 'admin';
     if (userRole === 'admin') {
              const adminToken = jwt.sign({ adminId: 'admin' }, process.env.JWT_SECRET, { expiresIn: '1h' });

              res.cookie('adminToken', adminToken, { httpOnly: true,  secure: true});
              return res.json({ message: 'Admin logged in successfully', role: userRole});
              
            } else if (userRole === 'user') {
              const userToken = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

              res.cookie('userToken', userToken, { httpOnly: true });
              return res.json({ message: 'User logged in successfully', role: userRole})
            }  
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
    // Retrieve user information from the database
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

    // Send the role along with the user data
    const role = usersWithApiCalls.length > 0 && usersWithApiCalls[0].role_id === 1 ? 'user' : 'admin';
    res.status(200).json({ users: usersWithApiCalls, role });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});



app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
