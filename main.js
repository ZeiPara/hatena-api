const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg'); // PostgreSQLを使う場合
const app = express();

const pool = new Pool({
  user: 'ZeiPara',
  host: 'localhost',
  database: 'hatena-database',
  password: '12345',
  port: 5432,
});

app.use(express.json()); // リクエストのボディをJSONとしてパース

// ユーザー登録エンドポイント
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // 必須項目の検証
  if (!username || !password) {
    return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });
  }

  const client = await pool.connect();
  
  try {
    // ユーザー名がすでに存在するかをチェック
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length > 0) {
      return res.status(400).json({ error: 'そのユーザー名はすでに存在しています' });
    }

    // パスワードのハッシュ化
    const hashedPassword = await bcrypt.hash(password, 10);

    // ユーザーをデータベースに追加
    await client.query(
      'INSERT INTO users (username, password) VALUES ($1, $2)',
      [username, hashedPassword]
    );

    // 成功レスポンス
    res.status(201).json({ message: 'ユーザー登録が完了しました' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラー' });
  } finally {
    client.release();
  }
});

// ログインエンドポイント
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // 必須項目の検証
  if (!username || !password) {
    return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });
  }

  const client = await pool.connect();
  
  try {
    // ユーザー名が存在するかを確認
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'ユーザー名またはパスワードが間違っています' });
    }

    const user = result.rows[0];

    // パスワードが一致するか確認
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ error: 'ユーザー名またはパスワードが間違っています' });
    }

    // JWTの発行
    const token = jwt.sign({ userId: user.id }, 'your-secret-key', { expiresIn: '1h' });

    // トークンを返す
    res.json({ message: 'ログイン成功', token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'サーバーエラー' });
  } finally {
    client.release();
  }
});

// サーバー起動
app.listen(3000, () => {
  console.log('Server running on port 3000');
});
