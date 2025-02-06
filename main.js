require('dotenv').config(); // 環境変数を読み込む
const express = require('express');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
app.use(cookieParser());
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.USER_DATABASE_URL,
});

const projectpool = new Pool({
  connectionString: process.env.PROJECT_DATABASE_URL,
});

// ユーザー認証用のミドルウェア
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'トークンが見つかりません' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT検証エラー:', err.message);
      return res.status(403).json({ error: 'トークンが無効です' });
    }
    req.user = user;
    next();
  });
};

// サーバーが動いていることを確認するログ
setInterval(() => console.log("サーバーは稼働中"), 10000);

const SCRATCH_AUTH_URL = 'https://auth.itinerary.eu.org/auth/';
const CALLBACK_URL = 'https://hatena-scratch.f5.si/auth/callback';

app.get('/scratch/check', async (req, res) => {
  const username = req.query.username; // ここでusernameを取得
  const client = await pool.connect(); // clientを接続
  const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
  client.release(); // 接続を解
}

app.get('/auth/login', async (req, res) => {
    const userId = req.query.userId; // ログイン中のサイトアカウントのIDを取得

    if (!userId) {
        return res.status(400).send('User ID is required');
    }

    const redirectLocation = Buffer.from(`${CALLBACK_URL}?userId=${userId}`).toString('base64');
    res.redirect(`${SCRATCH_AUTH_URL}?redirect=${redirectLocation}&name=hatena-scratch`);
});

app.get('/auth/callback', async (req, res) => {
    const { privateCode, userId } = req.query;

    if (!privateCode || !userId) {
        return res.status(400).send('Invalid request');
    }

    try {
        // Scratch Auth で privateCode を確認
        const response = await fetch(`https://auth.itinerary.eu.org/api/auth/verifyToken?privateCode=${privateCode}`);
        const data = await response.json();

        if (data.valid) {
            // PostgreSQL に保存（サイトアカウントと Scratch アカウントを紐付け）
            const client = await pool.connect();
            await client.query(
                `UPDATE users SET scratch_username = $1 WHERE id = $2`,
                [data.username, userId]
            );
            client.release();

            res.redirect('https://hatena-scratch.f5.si'); // アカウントページにリダイレクト
        } else {
            res.status(403).send('Authentication failed');
        }
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(500).send('Server error');
    }
});

// ルートエンドポイント
app.get('/', (req, res) => {
  res.send('正常に稼働しています');
});

// ユーザー情報取得
app.get('/user/:username', async (req, res) => {
  const username = req.params.username;
  console.log(`${username} のリクエストを受け付けました`);

  try {
    const result = await pool.query('SELECT username, profile FROM users WHERE username = $1', [username]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'ユーザーが見つかりません' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラー' });
  }
});

// ユーザー登録
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });
  }
  if (username.length > 30) {
    return res.status(400).json({ error: 'ユーザー名は30文字以内にしてください' });
  }
  if (password.length < 8 || !/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'パスワードは8文字以上で、英数字を含める必要があります' });
  }

  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length > 0) {
      return res.status(400).json({ error: 'そのユーザー名はすでに存在しています' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await client.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);

    res.status(201).json({ message: 'ユーザー登録が完了しました' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラー' });
  } finally {
    client.release();
  }
});

// 認証チェック
app.get('/auth/check', authenticateToken, (req, res) => {
  res.json({ isAuthenticated: true, user: req.user });
});

// プロジェクト作成
app.post('/createproject', authenticateToken, async (req, res) => {
  const { title, content } = req.body;
  const user = req.user.username;

  if (!title || !content) {
    return res.status(400).json({ error: 'タイトルと内容を入力してください' });
  }

  let d = new Date();
  let date = `${d.getFullYear()}/${d.getMonth() + 1}/${d.getDate()}`;

  const client = await projectpool.connect();
  try {
    await client.query(
      'INSERT INTO projects (user, content, date, title) VALUES ($1, $2, $3, $4)',
      [user, content, date, title]
    );
    res.status(201).json({ message: 'プロジェクトが作成されました' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラー' });
  } finally {
    client.release();
  }
});

// ログイン
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  console.log("ログインを受け付けました");
  if (!username || !password) {
    return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });
  }

  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'ユーザー名またはパスワードが間違っています' });
    }

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: 'ユーザー名またはパスワードが間違っています' });
    }

    const token = jwt.sign({ userId: user.id, username: username }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ message: 'ログイン成功', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラー' });
  } finally {
    client.release();
  }
});

// サーバー起動
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
