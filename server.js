const express = require('express');
const http = require("http");
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const url = require("url");
const cors = require('cors');
const app = express();
const port = 3000;
//hi
const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "moodboosterapi",
    port: 4100
    
});

app.use(cors()); 

connection.connect((err) => {
    if (err) {
        console.log("Connection error message: " + err.message);
        return;
    }

    // Create tables after successful connection
    createTables();
});

function createTables() {
    // SQL queries to create tables
    const createRolesTableQuery = `
        CREATE TABLE IF NOT EXISTS roles (
            id INT PRIMARY KEY,
            title VARCHAR(255),
            description TEXT
        )
    `;
    const createUsersTableQuery = `
        CREATE TABLE IF NOT EXISTS users (
            username VARCHAR(255) PRIMARY KEY,
            password VARCHAR(255),
            role_id INT,
            FOREIGN KEY (role_id) REFERENCES roles(id)
        )
    `;
    const createApiCallsTableQuery = `
        CREATE TABLE IF NOT EXISTS api_calls (
            user_name VARCHAR(255),
            call_count INT,
            FOREIGN KEY (user_name) REFERENCES users(username)
        )
    `;

    // Execute the SQL queries to create tables
    connection.query(createRolesTableQuery, (err, result) => {
        if (err) {
            console.log("Error creating roles table: " + err.message);
        } else {
            console.log("Roles table created successfully");
        }
    });

    connection.query(createUsersTableQuery, (err, result) => {
        if (err) {
            console.log("Error creating users table: " + err.message);
        } else {
            console.log("Users table created successfully");
        }
    });

    connection.query(createApiCallsTableQuery, (err, result) => {
        if (err) {
            console.log("Error creating api_calls table: " + err.message);
        } else {
            console.log("Api_calls table created successfully");
        }
    });
}

// Middleware to parse JSON bodies
app.use(express.json());


// Route for user registration
// Route for user registration
app.post('/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Check if username, email, and password are provided
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }

        // Hash the password with salt rounds
        const saltRounds = 10; // You can adjust this number as needed
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Save the user to the database
        connection.query('INSERT INTO users (username, email, password, role_id) VALUES (?, ?, ?, ?)', [username, email, hashedPassword, 1], (err, result) => {
            if (err) {
                console.log("Error registering user: " + err.message);
                res.status(500).json({ error: 'Internal Server Error' });
            } else {
                console.log("User registered successfully");
                // Initialize API calls with user's username
                connection.query('INSERT INTO api_calls (user_name, call_count) VALUES (?, ?)', [username, 0], (err, result) => {
                    if (err) {
                        console.log("Error initializing API calls for user: " + err.message);
                        res.status(500).json({ error: 'Internal Server Error' });
                    } else {
                        console.log("API calls initialized for user");
                        res.status(201).json({ message: 'User registered successfully' });
                    }
                });
            }
        });
    } catch (error) {
        console.error("Error registering user: " + error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api_call', (req, res) => {
});


// Route for user login
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Fetch the user from the database
        connection.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
            if (err) {
                console.log("Error logging in: " + err.message);
                res.status(500).json({ error: 'Internal Server Error' });
            } else if (results.length === 0) {
                res.status(401).json({ error: 'Invalid username or password' });
            } else {
                // Compare passwords
                const match = await bcrypt.compare(password, results[0].password);
                if (match) {
                    console.log("Login successful");
                    // Check the user's role ID
                    const roleID = results[0].role_id;
                    // Redirect based on role
                    if (roleID === 1) {
                        res.status(200).json({ message: 'Login successful', role: 'user' });
                    } else if (roleID === 2) {
                        res.status(200).json({ message: 'Login successful', role: 'admin' });
                    } else {
                        res.status(403).json({ error: 'Invalid role' });
                    }
                } else {
                    res.status(401).json({ error: 'Invalid username or password' });
                }
            }
        });
    } catch (error) {
        console.error("Error logging in: " + error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route to get users along with their associated API calls
app.get('/users', (req, res) => {
    const roleID = req.query.role_id; // Extract the role ID from the request query
    if (roleID !== '2') { // Check if the role ID is not for an admin
        return res.status(403).json({ error: 'Forbidden' }); // Send a Forbidden error response
    }

    // Proceed to fetch users if the role ID is for an admin
    connection.query(`
        SELECT u.username, u.email, u.role_id, COUNT(a.user_name) AS api_call_count
        FROM users u
        LEFT JOIN api_calls a ON u.username = a.user_name
        GROUP BY u.username, u.email, u.role_id;
    `, (err, results) => {
        if (err) {
            console.error("Error fetching users:", err.message);
            res.status(500).json({ error: 'Internal Server Error' });
        } else {
            res.json(results);
        }
    });
});


// Route to get all roles modify to verify perm status
app.get('/roles', (req, res) => {
    connection.query('SELECT * FROM roles', (err, results) => {
        if (err) {
            res.status(500).json({ error: 'Internal Server Error' });
        } else {
            res.json(results);
        }
    });
});


// Route to check if a username or email already exists
app.get('/checkuser', (req, res) => {
    const { username, email } = req.query;
    
    // Check if username or email exists
    connection.query('SELECT COUNT(*) AS usernameCount, COUNT(*) AS emailCount FROM users WHERE username = ? OR email = ?', [username, email], (err, results) => {
        if (err) {
            console.error("Error checking username and email: " + err.message);
            res.status(500).json({ error: 'Internal Server Error' });
        } else {
            const usernameCount = results[0].usernameCount;
            const emailCount = results[0].emailCount;
            res.status(200).json({ usernameUnique: usernameCount === 0, emailUnique: emailCount === 0 });
        }
    });
});


app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});

// Close the database connection when the server is stopped
process.on("SIGINT", () => {
    connection.end();
    console.log("Server stopped. Database connection closed.");
    process.exit();
});