const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();

const {
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY
} = process.env;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing Supabase environment variables');
  process.exit(1);
}

const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
const authClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

app.use(cors({
  origin: 'https://kevinchai.my.canva.site',
  methods: ['GET', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '2mb' }));

async function requireAdmin(req, res, next) {
  const token = req.get('Authorization')?.replace(/^Bearer\s+/i, '');

  if (!token) {
    return res.status(401).json({ error: '請先登入' });
  }

  const { data, error } = await authClient.auth.getUser(token);

  if (error || !data.user) {
    return res.status(401).json({ error: '登入已失效或無效' });
  }

  req.user = data.user;
  next();
}

app.get('/', (req, res) => res.send('Backup API is running'));

app.get('/api/data', requireAdmin, async (req, res) => {
  const { data, error } = await admin
    .from('site_backup')
    .select('data')
    .eq('id', 'main')
    .maybeSingle();

  if (error) {
    console.error(error);
    return res.status(500).json({ error: '讀取資料失敗' });
  }

  res.json(data ? data.data : null);
});

app.put('/api/data', requireAdmin, async (req, res) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ error: '資料格式錯誤' });
  }

  const { error } = await admin
    .from('site_backup')
    .upsert({
      id: 'main',
      data: req.body,
      updated_at: new Date().toISOString()
    });

  if (error) {
    console.error(error);
    return res.status(500).json({ error: '儲存資料失敗' });
  }

  res.json({ ok: true });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`API listening on ${port}`));
