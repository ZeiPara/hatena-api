const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const pool = new Pool({
  user: 'your-db-user',
  host: 'localhost',
  database: 'your-database',
  password: 'your-db-password',
  port: 5432,
});

app.use(express.json());

// サインインエンドポイント
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const client = await pool.connect();
  
  try {
    // ユーザーをデータベースから取得
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'ユーザーが見つかりません' });
    }

    const user = result.rows[0];

    // パスワード確認
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: 'パスワードが間違っています' });
    }

    // JWTを発行して返す
    const token = jwt.sign({ userId: user.id }, 'your-secret-key', { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラー' });
  } finally {
    client.release();
  }
});

// サーバー起動
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
