import dotenv from "dotenv"
dotenv.config()
import express from 'express';
import type { Request, Response, NextFunction  } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { authenticateToken } from './middleware';


const app = express();
const port = process.env.PORT;
const saltRounds = 10;
const EXPIRES_TIME = '1h';
const ALGORITHM = 'RS256';

app.use(express.json());

const privateKey = process.env.PRIVATE_KEY;

interface User {
  id: number;
  username: string;
  password: string;
}

const users: User[] = [
  {
      id: 1,
      username: 'admin',
      password: '$2b$10$0ODutXpdh720rUvpvhZWtOWX5tnKfKgKmU1AvJEApHpAwxYpTxINa' // 'admin'
  }
];

if (!port) {
  throw new Error('PORT environment variable is not set!');
}

if (!privateKey) {
  throw new Error('PRIVATE_KEY environment variable is not set!');
}else{
  console.log('PRIVATE_KEY is set');
  // console.log(privateKey);
}

// Extend the Request interface to include user property
declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}


// Use the privateKey (e.g., for signing JWTs, decrypting data, etc.)

app.get('/', (req: Request, res: Response) => {
  res.send('Hello from your TypeScript backend!');
});

app.listen(port, () => {
  // bcrypt.hash("admin", saltRounds, function(err, hash) {
  //   console.log(hash);
  // });
  console.log(`Server is running on port ${port}`);
});



app.post('/login', async (req: Request, res: Response) => {
  const { username, password } = req.body;

  const user = users.find(user => user.username === username);
  if (!user) {
    res.status(401).send('Invalid credentials');
    return 
      //return res.status(401).json({ message: 'Invalid credentials' });
  }

  try {


      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        res.status(401).send('Invalid credentials : password mismatch'); 
        return
          //return res.status(401).json({ message: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { sub: user.id, username: user.username }, 
        privateKey, 
        { 
          algorithm: ALGORITHM,
          expiresIn: EXPIRES_TIME ,  
        }
      );

      res.json({ token });
  } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ message: 'Login failed' });
  }
});




app.get('/protected', authenticateToken, (req: Request, res: Response) => {
  res.json({ 
    message: 'Protected data accessed successfully',
    user: req.user
  });
});

