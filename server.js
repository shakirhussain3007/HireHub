const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), { z } = require('zod');
const Database = require('better-sqlite3'), path = require('path');

const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
if (process.env.NODE_ENV === 'production' && !process.env.JWT_SECRET) throw new Error('JWT_SECRET required in production');
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'jobs.db'));
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('seeker','employer')));
CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY, employer_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, company TEXT NOT NULL, location TEXT NOT NULL, type TEXT NOT NULL, salary TEXT,
  description TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS applications(id INTEGER PRIMARY KEY, job_id INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, note TEXT, status TEXT DEFAULT 'pending'
  CHECK(status IN ('pending','shortlisted','rejected')), created_at TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(job_id,user_id));
`);

const app = express();
app.use(helmet({ contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'"] } } }));
app.use(express.json({ limit: '50kb' }));
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, max: 300 }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, max: 30 }));

// ---------- helpers ----------
class HttpError extends Error { constructor(s, m) { super(m); this.status = s; } }
const w = fn => (req, res, next) => { try { fn(req, res, next); } catch (e) { next(e); } };
const validate = schema => (req, res, next) => {
  const r = schema.safeParse(req.body);
  if (!r.success) return res.status(400).json({ error: 'Validation failed', details: r.error.issues.map(i => `${i.path.join('.')}: ${i.message}`) });
  req.body = r.data; next();
};
const auth = (req, res, next) => {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  try { req.user = jwt.verify(t, SECRET); next(); } catch { next(new HttpError(401, 'Login required')); }
};
const role = r => (req, res, next) => req.user.role === r ? next() : next(new HttpError(403, `Only ${r}s can do this`));
const sign = u => jwt.sign({ id: u.id, role: u.role, name: u.name }, SECRET, { expiresIn: '7d' });

const registerS = z.object({ name: z.string().trim().min(2).max(60), email: z.string().trim().toLowerCase().email(),
  password: z.string().min(8).max(100), role: z.enum(['seeker', 'employer']) });
const loginS = z.object({ email: z.string().trim().toLowerCase().email(), password: z.string().min(1) });
const jobS = z.object({ title: z.string().trim().min(3).max(100), company: z.string().trim().min(2).max(100),
  location: z.string().trim().min(2).max(100), type: z.enum(['Full-time', 'Part-time', 'Internship', 'Contract']),
  salary: z.string().trim().max(50).optional().default(''), description: z.string().trim().min(20).max(5000) });
const applyS = z.object({ note: z.string().trim().max(1000).optional().default('') });
const statusS = z.object({ status: z.enum(['pending', 'shortlisted', 'rejected']) });

// ---------- auth ----------
app.post('/api/auth/register', validate(registerS), w((req, res) => {
  const { name, email, password, role } = req.body;
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) throw new HttpError(409, 'Email already registered');
  const id = db.prepare('INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)').run(name, email, bcrypt.hashSync(password, 10), role).lastInsertRowid;
  const u = { id, name, role }; res.status(201).json({ token: sign(u), user: u });
}));
app.post('/api/auth/login', validate(loginS), w((req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(req.body.email);
  if (!u || !bcrypt.compareSync(req.body.password, u.password_hash)) throw new HttpError(401, 'Invalid email or password');
  res.json({ token: sign(u), user: { id: u.id, name: u.name, role: u.role } });
}));
app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

// ---------- jobs ----------
app.get('/api/jobs', w((req, res) => {
  const { q = '', location = '', type = '' } = req.query;
  const rows = db.prepare(`SELECT id,title,company,location,type,salary,description,created_at,employer_id FROM jobs
    WHERE (title LIKE @q OR company LIKE @q) AND location LIKE @l AND (@t='' OR type=@t) ORDER BY id DESC LIMIT 100`)
    .all({ q: `%${q}%`, l: `%${location}%`, t: String(type) });
  res.json(rows);
}));
app.get('/api/jobs/mine', auth, role('employer'), w((req, res) =>
  res.json(db.prepare(`SELECT j.*, (SELECT COUNT(*) FROM applications a WHERE a.job_id=j.id) AS applicants FROM jobs j WHERE employer_id=? ORDER BY id DESC`).all(req.user.id))));
app.get('/api/jobs/:id', w((req, res) => {
  const j = db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id);
  if (!j) throw new HttpError(404, 'Job not found'); res.json(j);
}));
app.post('/api/jobs', auth, role('employer'), validate(jobS), w((req, res) => {
  const b = req.body;
  const id = db.prepare('INSERT INTO jobs(employer_id,title,company,location,type,salary,description) VALUES(?,?,?,?,?,?,?)')
    .run(req.user.id, b.title, b.company, b.location, b.type, b.salary, b.description).lastInsertRowid;
  res.status(201).json({ id, ...b });
}));
app.put('/api/jobs/:id', auth, role('employer'), validate(jobS), w((req, res) => {
  const b = req.body;
  const r = db.prepare('UPDATE jobs SET title=?,company=?,location=?,type=?,salary=?,description=? WHERE id=? AND employer_id=?')
    .run(b.title, b.company, b.location, b.type, b.salary, b.description, req.params.id, req.user.id);
  if (!r.changes) throw new HttpError(404, 'Job not found or not yours'); res.json({ id: +req.params.id, ...b });
}));
app.delete('/api/jobs/:id', auth, role('employer'), w((req, res) => {
  const r = db.prepare('DELETE FROM jobs WHERE id=? AND employer_id=?').run(req.params.id, req.user.id);
  if (!r.changes) throw new HttpError(404, 'Job not found or not yours'); res.status(204).end();
}));

// ---------- applications ----------
app.post('/api/jobs/:id/apply', auth, role('seeker'), validate(applyS), w((req, res) => {
  if (!db.prepare('SELECT 1 FROM jobs WHERE id=?').get(req.params.id)) throw new HttpError(404, 'Job not found');
  try { db.prepare('INSERT INTO applications(job_id,user_id,note) VALUES(?,?,?)').run(req.params.id, req.user.id, req.body.note); }
  catch (e) { if (String(e.code).startsWith('SQLITE_CONSTRAINT')) throw new HttpError(409, 'Already applied'); throw e; }
  res.status(201).json({ message: 'Application submitted' });
}));
app.get('/api/applications/mine', auth, role('seeker'), w((req, res) =>
  res.json(db.prepare(`SELECT a.id,a.status,a.created_at,j.title,j.company FROM applications a JOIN jobs j ON j.id=a.job_id WHERE a.user_id=? ORDER BY a.id DESC`).all(req.user.id))));
app.get('/api/jobs/:id/applications', auth, role('employer'), w((req, res) => {
  if (!db.prepare('SELECT 1 FROM jobs WHERE id=? AND employer_id=?').get(req.params.id, req.user.id)) throw new HttpError(404, 'Job not found or not yours');
  res.json(db.prepare(`SELECT a.id,a.status,a.note,a.created_at,u.name,u.email FROM applications a JOIN users u ON u.id=a.user_id WHERE a.job_id=? ORDER BY a.id DESC`).all(req.params.id));
}));
app.patch('/api/applications/:id', auth, role('employer'), validate(statusS), w((req, res) => {
  const r = db.prepare(`UPDATE applications SET status=? WHERE id=? AND job_id IN (SELECT id FROM jobs WHERE employer_id=?)`).run(req.body.status, req.params.id, req.user.id);
  if (!r.changes) throw new HttpError(404, 'Application not found'); res.json({ status: req.body.status });
}));

app.get('/health', (_, res) => res.json({ ok: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  if (!err.status) console.error(err);
  res.status(err.status || 500).json({ error: err.status ? err.message : 'Internal server error' });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Job Portal running on :${PORT}`));
