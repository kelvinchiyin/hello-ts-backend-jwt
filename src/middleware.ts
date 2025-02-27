import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

// Add this after your existing imports
const publicKey = process.env.PUBLIC_KEY;

const ALGORITHM: jwt.Algorithm = (process.env.ALGORITHM as jwt.Algorithm) || 'RS256';

if (!publicKey) {
  throw new Error('PUBLIC_KEY environment variable is not set!');
}

// Extend the Request interface to include user property
declare global {
  namespace Express {
    interface Request {
      user?: any;
    }
  }
}

// Authentication middleware
export const authenticateToken = (req: Request, res: Response, next: NextFunction): void => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    res.sendStatus(401);
    return;
  }

  jwt.verify(token, process.env.PRIVATE_KEY as string, (err: any, user: any) => {
    if (err) {
      res.sendStatus(403);
      return;
    }
    req.user = user;
    next();
  });
};