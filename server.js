'use strict';

const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();

const {
  SUPABASE_URL,
  SUPABASE_ANON_KEY,
  SUPABASE_SERVICE_ROLE_KEY,
  SUPABASE_ADMIN_USER_ID,
  CORS_ORIGINS
} = process.env;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY || !SUPABASE_ADMIN_USER_ID) {
  console.error(
    'Missing required environment variables: SUPABASE_URL, SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_ADMIN_USER_ID'
  );
  process.exit(1);
}

// CORS_ORIGINS 必須是精確來源清單，以逗號分隔，不含路徑。
// 預設只允許原 Canva 網站。若管理頁也要直接呼叫 API，須在 Render 加入它的正式 HTTPS origin。
const allowedOrigins = new Set(
  (CORS_ORIGINS || 'https://kevinchai.my.canva.site')
    .split(',')
    .map((origin) => origin.trim().replace(/\/$/, ''))
    .filter(Boolean)
);

if (allowedOrigins.has('*')) {
  console.error('CORS_ORIGINS must not contain the wildcard *');
  process.exit(1);
}

const corsOptions = {
  origin(origin, callback) {
    // 無 Origin 的伺服器端請求仍須通過下面的 Bearer token 與管理員驗證。
    callback(null, !origin || allowedOrigins.has(origin));
  },
  methods: ['GET', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Authorization', 'Content-Type', 'If-Match'],
  exposedHeaders: ['ETag'],
  maxAge: 600,
  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '2mb', strict: true }));

const admin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});
const authClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});

const SENSITIVE_KEYS = new Set([
  'users',
  'password',
  'passwordhash',
  'passwd',
  'hash',
  'salt',
  'token',
  'accesstoken',
  'refreshtoken',
  'session',
  'cookie',
  'secret',
  'servicerole',
  'authorization',
  'apikey'
]);

function findSensitivePaths(value, path = '$', depth = 0, found = []) {
  if (depth > 40) {
    throw new Error('資料巢狀層級過深');
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      findSensitivePaths(item, `${path}[${index}]`, depth + 1, found);
    });
    return found;
  }

  if (value && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      const normalizedKey = key.toLowerCase().replace(/[_-]/g, '');
      if (SENSITIVE_KEYS.has(normalizedKey) || ['__proto__', 'prototype', 'constructor'].includes(key)) {
        found.push(`${path}.${key}`);
      } else {
        findSensitivePaths(child, `${path}.${key}`, depth + 1, found);
      }
    }
  }

  return found;
}

function requireAdmin(req, res, next) {
  (async () => {
    const authorization = req.get('Authorization') || '';
    const match = /^Bearer\s+(.+)$/i.exec(authorization);
    const token = match && match[1].trim();

    if (!token) {
      return res.status(401).json({ error: '請先登入' });
    }

    // 由 Supabase Auth 驗證 token 並取得真實 user.id；不信任前端傳入的使用者資訊。
    const { data, error } = await authClient.auth.getUser(token);
    if (error || !data || !data.user) {
      return res.status(401).json({ error: '登入已失效或無效' });
    }

    if (data.user.id !== SUPABASE_ADMIN_USER_ID) {
      return res.status(403).json({ error: '此帳號沒有備份管理權限' });
    }

    req.user = data.user;
    return next();
  })().catch((error) => {
    console.error('Authentication check failed:', error && error.message ? error.message : 'unknown error');
    if (!res.headersSent) res.status(500).json({ error: '驗證服務暫時無法使用' });
  });
}

function parseIfMatch(value) {
  if (!value) return null;
  const match = /^(?:W\/)?"?(\d+)"?$/.exec(value.trim());
  if (!match) return null;
  const version = Number(match[1]);
  return Number.isSafeInteger(version) ? version : null;
}

app.get('/', (req, res) => {
  res.type('text/plain').send('Backup API is running');
});

app.get('/api/data', requireAdmin, async (req, res) => {
  try {
    const { data, error } = await admin
      .from('site_backup')
      .select('data,version,updated_at')
      .eq('id', 'main')
      .maybeSingle();

    if (error) {
      console.error('Backup read failed:', error.message);
      return res.status(500).json({ error: '讀取資料失敗' });
    }

    const version = data ? Number(data.version) : 0;
    res.set('ETag', `"${version}"`);
    return res.json({
      data: data ? data.data : null,
      version,
      updated_at: data ? data.updated_at : null
    });
  } catch (error) {
    console.error('Backup read failed:', error && error.message ? error.message : 'unknown error');
    return res.status(500).json({ error: '讀取資料失敗' });
  }
});

app.put('/api/data', requireAdmin, async (req, res) => {
  if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
    return res.status(400).json({ error: '資料格式錯誤：必須是 JSON 物件' });
  }

  const expectedVersion = parseIfMatch(req.get('If-Match'));
  if (expectedVersion === null) {
    return res.status(428).json({ error: '缺少有效的 If-Match 版本；請先重新讀取雲端資料' });
  }

  let sensitivePaths;
  try {
    sensitivePaths = findSensitivePaths(req.body);
  } catch (error) {
    return res.status(400).json({ error: error.message || '資料結構不合法' });
  }

  if (sensitivePaths.length) {
    return res.status(400).json({
      error: '備份包含禁止上傳的認證欄位；請先在前端安全移除後再試',
      fields: sensitivePaths.slice(0, 20)
    });
  }

  try {
    const { data, error } = await admin.rpc('put_site_backup_if_version', {
      p_id: 'main',
      p_data: req.body,
      p_expected_version: expectedVersion
    });

    if (error) {
      console.error('Backup write failed:', error.message);
      return res.status(500).json({ error: '儲存資料失敗；請確認資料庫版本控制函式已安裝' });
    }

    const result = Array.isArray(data) ? data[0] : data;
    if (!result || typeof result.ok !== 'boolean') {
      console.error('Backup write failed: unexpected RPC response');
      return res.status(500).json({ error: '儲存服務回傳格式錯誤' });
    }

    const currentVersion = Number(result.current_version);
    res.set('ETag', `"${currentVersion}"`);

    if (!result.ok) {
      return res.status(409).json({
        error: '雲端備份已被更新；未覆寫資料，請重新下載並比較後再決定',
        currentVersion
      });
    }

    return res.json({ ok: true, version: currentVersion });
  } catch (error) {
    console.error('Backup write failed:', error && error.message ? error.message : 'unknown error');
    return res.status(500).json({ error: '儲存資料失敗' });
  }
});

// 避免把 JSON body、token 或資料庫錯誤細節回傳給瀏覽器。
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);

  if (error && error.type === 'entity.too.large') {
    return res.status(413).json({ error: '資料超過 2 MB 限制' });
  }
  if (error && error.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'JSON 格式錯誤' });
  }

  console.error('Unhandled request error:', error && error.message ? error.message : 'unknown error');
  return res.status(500).json({ error: '伺服器內部錯誤' });
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`API listening on ${port}`));
