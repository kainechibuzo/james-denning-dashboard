import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import session from 'express-session';
import pg from 'pg';
import connectPgSimple from 'connect-pg-simple';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import rateLimit from 'express-rate-limit';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 10000;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || 'kainechibuzo@gmail.com').toLowerCase();
const pool = process.env.DATABASE_URL ? new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('render.com') ? { rejectUnauthorized: false } : undefined,
}) : null;
const PgSession = connectPgSimple(session);
const s3Ready = ['S3_ENDPOINT','S3_BUCKET','S3_ACCESS_KEY_ID','S3_SECRET_ACCESS_KEY'].every(k => process.env[k]);
const s3 = s3Ready ? new S3Client({
  region: process.env.S3_REGION || 'auto',
  endpoint: process.env.S3_ENDPOINT,
  forcePathStyle: true,
  credentials: { accessKeyId: process.env.S3_ACCESS_KEY_ID, secretAccessKey: process.env.S3_SECRET_ACCESS_KEY }
}) : null;

app.set('trust proxy', 1);
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: process.env.APP_ORIGIN ? process.env.APP_ORIGIN.split(',').map(x => x.trim()) : true, credentials: true }));
app.use(express.json({ limit: '1mb' }));
if (process.env.SESSION_SECRET) {
  app.use(session({
    store: pool ? new PgSession({ pool, createTableIfMissing: true, tableName: 'user_sessions' }) : undefined,
    name: 'jd.sid',
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
  }));
}
app.use(express.static(path.join(__dirname, 'public')));

async function initDb() {
  if (!pool) return;
  await pool.query(`
    CREATE TABLE IF NOT EXISTS jd_products (
      id UUID PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      description TEXT NOT NULL DEFAULT '',
      version TEXT NOT NULL DEFAULT '1.0.0',
      category TEXT NOT NULL DEFAULT 'Apps',
      storage_key TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size_bytes BIGINT NOT NULL,
      published BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS jd_download_tokens (
      token_hash TEXT PRIMARY KEY,
      product_id UUID NOT NULL REFERENCES jd_products(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      revoked BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS jd_download_events (
      id BIGSERIAL PRIMARY KEY,
      product_id UUID REFERENCES jd_products(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}
const dbRequired = (req,res,next) => {
  if (!pool) return res.status(503).json({ error: 'Database is not configured. Set DATABASE_URL in Render.' });
  next();
};
const adminOnly = (req,res,next) => {
  if (!req.session?.adminEmail || req.session.adminEmail !== ADMIN_EMAIL) return res.status(401).json({ error: 'Admin sign-in required.' });
  next();
};
const slugify = s => s.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,70) || 'product';
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 250 * 1024 * 1024 }, fileFilter: (_req,file,cb) => cb(null, !!file.originalname) });
const safeProduct = row => ({ id:row.id, name:row.name, slug:row.slug, description:row.description, version:row.version, category:row.category, sizeBytes:Number(row.size_bytes), published:row.published, createdAt:row.created_at });

app.get('/api/health', async (_req,res) => {
  let database = 'not-configured';
  if (pool) { try { await pool.query('SELECT 1'); database = 'ok'; } catch { database = 'error'; } }
  res.status(database === 'error' ? 503 : 200).json({ status: database === 'error' ? 'degraded' : 'ok', service:'james-denning-dashboard', database, storage:s3 ? 'configured' : 'not-configured', timestamp:new Date().toISOString() });
});
app.get('/api/products', dbRequired, async (_req,res,next) => {
  try { const { rows } = await pool.query('SELECT * FROM jd_products WHERE published = TRUE ORDER BY created_at DESC'); res.json(rows.map(safeProduct)); } catch(e){next(e);}
});
app.get('/api/admin/session', (req,res) => res.json({ authenticated: !!req.session?.adminEmail, email:req.session?.adminEmail || null, adminEmail:ADMIN_EMAIL }));
app.post('/api/admin/login', rateLimit({ windowMs:15*60*1000, limit:10, standardHeaders:true, legacyHeaders:false }), (req,res) => {
  if (!process.env.ADMIN_PASSWORD_HASH || !process.env.SESSION_SECRET) return res.status(503).json({ error:'Set ADMIN_PASSWORD_HASH and SESSION_SECRET in Render environment variables first.' });
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  if (email !== ADMIN_EMAIL || !bcrypt.compareSync(password, process.env.ADMIN_PASSWORD_HASH)) return res.status(401).json({ error:'Invalid sign-in details.' });
  req.session.adminEmail = email;
  req.session.save(err => err ? res.status(500).json({error:'Could not start session.'}) : res.json({authenticated:true,email}));
});
app.post('/api/admin/logout', (req,res) => req.session?.destroy(() => res.json({ok:true})));
app.get('/api/admin/products', dbRequired, adminOnly, async (_req,res,next) => {
  try { const { rows } = await pool.query('SELECT * FROM jd_products ORDER BY created_at DESC'); res.json(rows.map(safeProduct)); } catch(e){next(e);}
});
app.post('/api/admin/products', dbRequired, adminOnly, upload.single('file'), async (req,res,next) => {
  try {
    if (!s3) return res.status(503).json({error:'Persistent object storage is not configured. Set S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID and S3_SECRET_ACCESS_KEY.'});
    if (!req.file) return res.status(400).json({error:'Choose a product file to upload.'});
    const name = String(req.body.name || '').trim().slice(0,120);
    if (!name) return res.status(400).json({error:'Product name is required.'});
    const id = crypto.randomUUID();
    const base = slugify(name);
    const slug = base + '-' + id.slice(0,8);
    const storageKey = `products/${id}/${crypto.randomBytes(12).toString('hex')}-${path.basename(req.file.originalname).replace(/[^a-zA-Z0-9._-]/g,'_')}`;
    await s3.send(new PutObjectCommand({Bucket:process.env.S3_BUCKET,Key:storageKey,Body:req.file.buffer,ContentType:req.file.mimetype || 'application/octet-stream'}));
    const { rows } = await pool.query(
      'INSERT INTO jd_products (id,name,slug,description,version,category,storage_key,original_filename,mime_type,size_bytes,published) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
      [id,name,slug,String(req.body.description||'').slice(0,3000),String(req.body.version||'1.0.0').slice(0,40),String(req.body.category||'Apps').slice(0,80),storageKey,path.basename(req.file.originalname),req.file.mimetype||'application/octet-stream',req.file.size,req.body.published !== 'false']
    );
    res.status(201).json(safeProduct(rows[0]));
  } catch(e){next(e);}
});
app.patch('/api/admin/products/:id', dbRequired, adminOnly, async (req,res,next) => {
  try {
    const { rows } = await pool.query('UPDATE jd_products SET published=COALESCE($2,published), name=COALESCE($3,name), description=COALESCE($4,description), version=COALESCE($5,version), updated_at=NOW() WHERE id=$1 RETURNING *', [req.params.id, typeof req.body.published==='boolean'?req.body.published:null, typeof req.body.name==='string'?req.body.name.trim().slice(0,120):null, typeof req.body.description==='string'?req.body.description.slice(0,3000):null, typeof req.body.version==='string'?req.body.version.slice(0,40):null]);
    if (!rows[0]) return res.status(404).json({error:'Product not found.'});
    res.json(safeProduct(rows[0]));
  } catch(e){next(e);}
});
app.delete('/api/admin/products/:id', dbRequired, adminOnly, async (req,res,next) => {
  try {
    if (!s3) return res.status(503).json({error:'Persistent object storage is not configured.'});
    const { rows } = await pool.query('DELETE FROM jd_products WHERE id=$1 RETURNING storage_key', [req.params.id]);
    if (!rows[0]) return res.status(404).json({error:'Product not found.'});
    await s3.send(new DeleteObjectCommand({Bucket:process.env.S3_BUCKET,Key:rows[0].storage_key}));
    res.json({ok:true});
  } catch(e){next(e);}
});
app.post('/api/admin/products/:id/download-link', dbRequired, adminOnly, async (req,res,next) => {
  try {
    const { rows } = await pool.query('SELECT id FROM jd_products WHERE id=$1', [req.params.id]);
    if (!rows[0]) return res.status(404).json({error:'Product not found.'});
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const hours = Math.min(168,Math.max(1,Number(req.body?.expiresInHours)||24));
    await pool.query('INSERT INTO jd_download_tokens(token_hash,product_id,expires_at) VALUES($1,$2,NOW()+($3 * INTERVAL \'1 hour\'))',[tokenHash,req.params.id,hours]);
    res.status(201).json({url:`${req.protocol}://${req.get('host')}/api/download/${rawToken}`,expiresInHours:hours});
  } catch(e){next(e);}
});
app.post('/api/admin/download-links/:token/revoke', dbRequired, adminOnly, async (req,res,next) => {
  try { const hash=crypto.createHash('sha256').update(req.params.token).digest('hex'); const r=await pool.query('UPDATE jd_download_tokens SET revoked=TRUE WHERE token_hash=$1',[hash]); res.json({ok:r.rowCount>0}); } catch(e){next(e);}
});
app.get('/api/download/:token', dbRequired, async (req,res,next) => {
  try {
    if (!s3) return res.status(503).send('Download storage is not configured.');
    const hash=crypto.createHash('sha256').update(req.params.token).digest('hex');
    const { rows }=await pool.query('SELECT t.product_id,p.storage_key,p.original_filename,p.mime_type FROM jd_download_tokens t JOIN jd_products p ON p.id=t.product_id WHERE t.token_hash=$1 AND t.revoked=FALSE AND t.expires_at>NOW()',[hash]);
    if (!rows[0]) return res.status(404).send('This download link is invalid, expired, or revoked.');
    await pool.query('INSERT INTO jd_download_events(product_id) VALUES($1)',[rows[0].product_id]);
    const url=await getSignedUrl(s3,new GetObjectCommand({Bucket:process.env.S3_BUCKET,Key:rows[0].storage_key,ResponseContentDisposition:`attachment; filename="${rows[0].original_filename.replace(/["\\\\]/g,'_')}"`,ResponseContentType:rows[0].mime_type}),{expiresIn:300});
    res.redirect(302,url);
  } catch(e){next(e);}
});
app.get('/api/admin/metrics', dbRequired, adminOnly, async (_req,res,next) => {
  try {
    const [products,downloads,recent]=await Promise.all([
      pool.query('SELECT COUNT(*)::int AS count FROM jd_products'),
      pool.query('SELECT COUNT(*)::int AS count FROM jd_download_events'),
      pool.query('SELECT id,name,created_at FROM jd_products ORDER BY created_at DESC LIMIT 5')
    ]);
    res.json({products:products.rows[0].count,downloads:downloads.rows[0].count,recent:recent.rows});
  } catch(e){next(e);}
});
app.use((err,_req,res,_next) => { console.error(err); if (res.headersSent) return; res.status(500).json({error:'Unexpected server error.'}); });
app.get('*all', (_req,res) => res.sendFile(path.join(__dirname,'public','index.html')));
initDb().then(()=>app.listen(PORT,'0.0.0.0',()=>console.log(`James Denning dashboard listening on ${PORT}`))).catch(err=>{console.error('Database initialization failed',err);process.exit(1);});
