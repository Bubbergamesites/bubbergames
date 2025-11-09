import bcrypt from 'bcrypt';
import db from '../db.js';
import { randomUUID, randomBytes } from 'crypto';
import { sendVerificationEmail } from '../email.js';

export async function signupHandler(req, res) {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try {
    const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const userId = randomUUID();
    const verificationToken = randomBytes(32).toString('hex');
    const now = Date.now();

    const isFirstUser = db.prepare('SELECT COUNT(*) AS count FROM users').get().count === 0;
    const isAdmin = isFirstUser || email === 'petezahgames@gmail.com';

    db.prepare(`
      INSERT INTO users (id, email, password_hash, verification_token, created_at, updated_at, is_admin, email_verified)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(userId, email, passwordHash, verificationToken, now, now, isAdmin ? 1 : 0, isFirstUser ? 1 : 0);

    if (isFirstUser) {
      const protocol = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
      const host = req.headers.host;
      await sendVerificationEmail(email, verificationToken, protocol, host);
      return res.status(201).json({ message: 'Admin account created! Check your email to verify.' });
    }

    const protocol = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
    const host = req.headers.host;
    const emailSent = await sendVerificationEmail(email, verificationToken, protocol, host);

    res.status(201).json({ 
      message: emailSent 
        ? 'Account created! Please check your email to verify your account.' 
        : 'Account created, but verification email failed to send. Please contact support.',
      emailSent
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
}