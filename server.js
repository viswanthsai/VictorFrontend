const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const fs = require('fs').promises;
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');

// Initialize express app
const app = express();
const PORT = process.env.PORT || 9000;

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-for-development-only';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// Data file paths
const USERS_FILE = path.join(__dirname, 'data', 'users.json');
const TASKS_FILE = path.join(__dirname, 'data', 'tasks.json');

// Ensure data directory exists
async function ensureDataDirExists() {
  const dataDir = path.join(__dirname, 'data');
  try {
    await fs.access(dataDir);
  } catch (error) {
    if (error.code === 'ENOENT') {
      await fs.mkdir(dataDir, { recursive: true });
      
      // Create empty data files if they don't exist
      await fs.writeFile(USERS_FILE, '[]');
      await fs.writeFile(TASKS_FILE, '[]');
    } else {
      throw error;
    }
  }
}

// Helper to read data files
async function readData(filePath) {
  try {
    const data = await fs.readFile(filePath, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    if (error.code === 'ENOENT') {
      // File doesn't exist, return empty array
      return [];
    }
    throw error;
  }
}

// Helper to write data files
async function writeData(filePath, data) {
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), 'utf8');
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    
    req.user = user;
    next();
  });
}

// Server status endpoint
app.get('/api/status', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Server is running',
    timestamp: new Date().toISOString()
  });
});

// User registration
app.post('/api/signup', async (req, res) => {
  try {
    const { fullname, email, password } = req.body;
    
    // Validation
    if (!fullname || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    
    // Check email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ message: 'Invalid email format' });
    }
    
    // Read existing users
    const users = await readData(USERS_FILE);
    
    // Check if email already exists
    const existingUser = users.find(user => user.email.toLowerCase() === email.toLowerCase());
    if (existingUser) {
      return res.status(409).json({ message: 'Email already in use' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user
    const newUser = {
      id: users.length > 0 ? Math.max(...users.map(u => u.id)) + 1 : 1,
      fullname,
      email,
      password: hashedPassword,
      createdAt: new Date().toISOString(),
      role: 'user'
    };
    
    // Add to users array
    users.push(newUser);
    
    // Write back to file
    await writeData(USERS_FILE, users);
    
    // Generate JWT token
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, role: newUser.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Return user info and token (excluding password)
    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json({
      token,
      userId: newUser.id,
      username: newUser.fullname,
      message: 'User registered successfully'
    });
  } catch (error) {
    console.error('Error in /api/signup:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// User login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validation
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    // Read users
    const users = await readData(USERS_FILE);
    
    // Find user by email
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    // Compare passwords
    let passwordMatch;
    
    // Handle both bcrypt and plain SHA-256 hashes (for demo data)
    if (user.password.startsWith('$2b$')) {
      // Bcrypt hash
      passwordMatch = await bcrypt.compare(password, user.password);
    } else {
      // For demo purposes - plain SHA-256 comparison
      // In production, always use bcrypt
      const crypto = require('crypto');
      const hash = crypto.createHash('sha256').update(password).digest('hex');
      passwordMatch = (hash === user.password);
    }
    
    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    // Return user info and token
    res.json({
      token,
      userId: user.id,
      username: user.fullname,
      message: 'Login successful'
    });
  } catch (error) {
    console.error('Error in /api/login:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get current user profile
app.get('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const users = await readData(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    
    // Return limited public info
    const publicProfile = {
      id: user.id,
      fullname: user.fullname,
      createdAt: user.createdAt
    };
    
    res.status(200).json(publicProfile);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Server error while fetching user' });
  }
});

// Update user profile
app.put('/api/users/me', authenticateToken, async (req, res) => {
  try {
    const { fullname, phone, location } = req.body;
    const users = await readJsonFile(USERS_FILE);
    const userIndex = users.findIndex(u => u.id === req.user.id);
    
    if (userIndex === -1) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    // Update fields
    if (fullname) users[userIndex].fullname = fullname;
    if (phone !== undefined) users[userIndex].phone = phone;
    if (location !== undefined) users[userIndex].location = location;
    
    // Add updated timestamp
    users[userIndex].updatedAt = new Date().toISOString();
    
    await writeJsonFile(USERS_FILE, users);
    
    // Return updated user without password
    const { password, ...updatedUser } = users[userIndex];
    res.status(200).json(updatedUser);
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ message: 'Server error while updating user' });
  }
});

// TASK ENDPOINTS

// Get all tasks
app.get('/api/tasks', async (req, res) => {
  try {
    const tasks = await readJsonFile(TASKS_FILE);
    res.status(200).json(tasks);
  } catch (error) {
    console.error('Error fetching tasks:', error);
    res.status(500).json({ message: 'Server error while fetching tasks' });
  }
});

// Get task by ID
app.get('/api/tasks/:id', async (req, res) => {
  try {
    const tasks = await readJsonFile(TASKS_FILE);
    const task = tasks.find(t => t.id === parseInt(req.params.id));
    
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    res.status(200).json(task);
  } catch (error) {
    console.error('Error fetching task:', error);
    res.status(500).json({ message: 'Server error while fetching task' });
  }
});

// Create a new task
app.post('/api/tasks', authenticateToken, async (req, res) => {
  try {
    const { title, description, category, location, budget, deadline } = req.body;
    
    // Validation
    if (!title || !description) {
      return res.status(400).json({ message: 'Title and description are required' });
    }
    
    // Get user info
    const users = await readJsonFile(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const tasks = await readJsonFile(TASKS_FILE);
    
    // Create new task
    const newTask = {
      id: tasks.length > 0 ? Math.max(...tasks.map(t => t.id)) + 1 : 1,
      title,
      description,
      category: category || 'Other',
      location: location || 'Remote',
      budget: budget ? parseInt(budget) : null,
      deadline: deadline || null,
      status: 'Open',
      createdAt: new Date().toISOString(),
      userId: user.id,
      createdBy: user.fullname
    };
    
    tasks.push(newTask);
    await writeJsonFile(TASKS_FILE, tasks);
    
    res.status(201).json(newTask);
  } catch (error) {
    console.error('Error creating task:', error);
    res.status(500).json({ message: 'Server error while creating task' });
  }
});

// Update a task
app.put('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id);
    const { title, description, category, location, budget, deadline, status } = req.body;
    
    const tasks = await readJsonFile(TASKS_FILE);
    const taskIndex = tasks.findIndex(t => t.id === taskId);
    
    if (taskIndex === -1) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Check if user is authorized to update this task
    if (tasks[taskIndex].userId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'You are not authorized to update this task' });
    }
    
    // Update fields if provided
    if (title) tasks[taskIndex].title = title;
    if (description) tasks[taskIndex].description = description;
    if (category) tasks[taskIndex].category = category;
    if (location) tasks[taskIndex].location = location;
    if (budget !== undefined) tasks[taskIndex].budget = budget ? parseInt(budget) : null;
    if (deadline !== undefined) tasks[taskIndex].deadline = deadline;
    if (status) tasks[taskIndex].status = status;
    
    // Add updated timestamp
    tasks[taskIndex].updatedAt = new Date().toISOString();
    
    await writeJsonFile(TASKS_FILE, tasks);
    
    res.status(200).json(tasks[taskIndex]);
  } catch (error) {
    console.error('Error updating task:', error);
    res.status(500).json({ message: 'Server error while updating task' });
  }
});

// Accept a task
app.post('/api/tasks/:id/accept', authenticateToken, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id);
    
    const tasks = await readJsonFile(TASKS_FILE);
    const taskIndex = tasks.findIndex(t => t.id === taskId);
    
    if (taskIndex === -1) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Can't accept your own task
    if (tasks[taskIndex].userId === req.user.id) {
      return res.status(400).json({ message: 'You cannot accept your own task' });
    }
    
    // Check if task is already accepted
    if (tasks[taskIndex].status !== 'Open') {
      return res.status(400).json({ message: 'This task is not open for acceptance' });
    }
    
    // Get user info
    const users = await readJsonFile(USERS_FILE);
    const user = users.find(u => u.id === req.user.id);
    
    // Accept task
    tasks[taskIndex].status = 'In Progress';
    tasks[taskIndex].acceptedById = req.user.id;
    tasks[taskIndex].acceptedByName = user ? user.fullname : 'User';
    tasks[taskIndex].acceptedAt = new Date().toISOString();
    tasks[taskIndex].updatedAt = new Date().toISOString();
    
    await writeJsonFile(TASKS_FILE, tasks);
    
    res.status(200).json({
      message: 'Task accepted successfully',
      task: tasks[taskIndex]
    });
  } catch (error) {
    console.error('Error accepting task:', error);
    res.status(500).json({ message: 'Server error while accepting task' });
  }
});

// Complete a task
app.post('/api/tasks/:id/complete', authenticateToken, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id);
    
    const tasks = await readJsonFile(TASKS_FILE);
    const taskIndex = tasks.findIndex(t => t.id === taskId);
    
    if (taskIndex === -1) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Check if user is authorized (task creator or accepter)
    if (tasks[taskIndex].userId !== req.user.id && 
        tasks[taskIndex].acceptedById !== req.user.id && 
        req.user.role !== 'admin') {
      return res.status(403).json({ message: 'You are not authorized to complete this task' });
    }
    
    // Check if task is in progress
    if (tasks[taskIndex].status !== 'In Progress') {
      return res.status(400).json({ message: 'Only tasks in progress can be completed' });
    }
    
    // Complete task
    tasks[taskIndex].status = 'Completed';
    tasks[taskIndex].completedAt = new Date().toISOString();
    tasks[taskIndex].updatedAt = new Date().toISOString();
    
    await writeJsonFile(TASKS_FILE, tasks);
    
    res.status(200).json({
      message: 'Task marked as completed',
      task: tasks[taskIndex]
    });
  } catch (error) {
    console.error('Error completing task:', error);
    res.status(500).json({ message: 'Server error while completing task' });
  }
});

// Delete a task
app.delete('/api/tasks/:id', authenticateToken, async (req, res) => {
  try {
    const taskId = parseInt(req.params.id);
    
    const tasks = await readJsonFile(TASKS_FILE);
    const taskIndex = tasks.findIndex(t => t.id === taskId);
    
    if (taskIndex === -1) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Check if user is authorized to delete this task
    if (tasks[taskIndex].userId !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'You are not authorized to delete this task' });
    }
    
    // Remove the task
    tasks.splice(taskIndex, 1);
    await writeJsonFile(TASKS_FILE, tasks);
    
    res.status(200).json({ message: 'Task deleted successfully' });
  } catch (error) {
    console.error('Error deleting task:', error);
    res.status(500).json({ message: 'Server error while deleting task' });
  }
});

// Get tasks for current user (both created and accepted)
app.get('/api/my-tasks', authenticateToken, async (req, res) => {
  try {
    const tasks = await readJsonFile(TASKS_FILE);
    
    // Filter tasks related to current user
    const userTasks = tasks.filter(
      task => task.userId === req.user.id || task.acceptedById === req.user.id
    );
    
    res.status(200).json(userTasks);
  } catch (error) {
    console.error('Error fetching user tasks:', error);
    res.status(500).json({ message: 'Server error while fetching user tasks' });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Victor backend server running on port ${PORT}`);
  
  // Create data directory and files if they don't exist
  (async () => {
    try {
      await fs.mkdir(path.join(__dirname, 'data'), { recursive: true });
      
      // Check if users file exists, if not create it
      try {
        await fs.access(USERS_FILE);
      } catch {
        await fs.writeFile(USERS_FILE, JSON.stringify([
          {
            id: 1,
            fullname: "Demo User",
            email: "demo@example.com",
            password: "$2b$10$5XXJS.T62uvg4UKMEMnWO.6k5MeXazhj82nb1F10XBw8fOwR/bAZy", // "password123"
            createdAt: new Date().toISOString(),
            role: "user"
          }
        ], null, 2));
        console.log('Created default users file');
      }
      
      // Check if tasks file exists, if not create it
      try {
        await fs.access(TASKS_FILE);
      } catch {
        await fs.writeFile(TASKS_FILE, JSON.stringify([
          {
            id: 1,
            title: "Sample Task",
            description: "This is a sample task to demonstrate how Victor works",
            category: "Other",
            location: "Remote",
            budget: 500,
            status: "Open",
            createdAt: new Date().toISOString(),
            userId: 1,
            createdBy: "Demo User"
          }
        ], null, 2));
        console.log('Created default tasks file');
      }
    } catch (error) {
      console.error('Error setting up data files:', error);
    }
  })();
});

module.exports = app; // Export for testing if needed
