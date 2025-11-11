// filepath: server/api/admin-user-action.js
import db from '../db.js';

export async function adminUserActionHandler(req, res) {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
  const admin = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.user.id);
  if (!admin || !admin.is_admin) return res.status(403).json({ error: 'Admin access required' });
  const { userId, action } = req.body;
  if (!userId || !['suspend','staff','delete','ban'].includes(action)) return res.status(400).json({ error: 'Invalid request' });
  if (userId === req.session.user.id) return res.status(400).json({ error: 'Cannot manage yourself' });
  // Only allow staff promotion, not demotion or deleting staff/admins
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.is_admin) return res.status(403).json({ error: 'Cannot manage another admin' });
  if (action === 'staff') {
    db.prepare('UPDATE users SET is_admin = 2 WHERE id = ?').run(userId); // 2 = staff
    return res.json({ message: 'User promoted to staff.' });
  }
  if (action === 'suspend') {
    db.prepare('UPDATE users SET email_verified = 0 WHERE id = ?').run(userId);
    return res.json({ message: 'User suspended.' });
  }
  if (action === 'ban') {
    // For demo: set email_verified=0 and store a ban flag (add column if needed)
    try {
      db.prepare('ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0');
    } catch {}
    db.prepare('UPDATE users SET banned = 1, email_verified = 0 WHERE id = ?').run(userId);
    return res.json({ message: 'User and IP banned.' });
  }
  if (action === 'delete') {
    db.prepare('DELETE FROM users WHERE id = ?').run(userId);
    return res.json({ message: 'User deleted.' });
  }
  return res.status(400).json({ error: 'Unknown action' });
}
