require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const cors = require('cors');
const path = require('path');

const app = express();

app.use(express.json());
app.use(cors());

// 👉 SERVIR FRONTEND (página bonita en public/)
app.use(express.static(path.join(__dirname, 'public')));

// Conexión a PostgreSQL RDS
const pool = new Pool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: { rejectUnauthorized: false }
});


// Registro de usuario
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id,email',
      [email, hash]
    );

    res.json({ message: 'Usuario registrado', user: result.rows[0] });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error al registrar' });
  }
});

// Login (primer paso)
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];

  if (!user) return res.status(401).json({ error: 'Usuario no existe' });

  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Contraseña incorrecta' });

  // Token temporal para 2FA
  const tempToken = jwt.sign(
    { userId: user.id },
    process.env.JWT_SECRET,
    { expiresIn: '5m' }
  );

  res.json({
    tempToken,
    twofa_enabled: user.twofa_enabled,
    message: 'Ingresa tu código 2FA'
  });
});

// Activar 2FA
app.post('/2fa/setup', async (req, res) => {
  try {
    const { tempToken } = req.body;

    const { userId } = jwt.verify(tempToken, process.env.JWT_SECRET);

    const secret = speakeasy.generateSecret({
      name: 'MiApp AWS - 2FA',
    });

    await pool.query(
      'UPDATE users SET twofa_secret = $1, twofa_enabled = true WHERE id = $2',
      [secret.base32, userId]
    );

    const qr = await qrcode.toDataURL(secret.otpauth_url);

    res.json({
      message: 'Escanea este código con Google Authenticator',
      qr,
      otpauth_url: secret.otpauth_url
    });

  } catch (e) {
    console.log(e);
    res.status(500).json({ error: 'Error al generar 2FA' });
  }
});

// Verificar 2FA
app.post('/2fa/verify', async (req, res) => {
  try {
    const { tempToken, token } = req.body;

    const { userId } = jwt.verify(tempToken, process.env.JWT_SECRET);

    const result = await pool.query('SELECT twofa_secret FROM users WHERE id = $1', [userId]);
    const user = result.rows[0];

    if (!user) return res.status(400).json({ error: 'Usuario no encontrado' });

    const verified = speakeasy.totp.verify({
      secret: user.twofa_secret,
      encoding: 'base32',
      token,
    });

    if (!verified) return res.status(401).json({ error: 'Código 2FA incorrecto' });

    const accessToken = jwt.sign(
      { userId },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({
      message: 'Acceso exitoso',
      accessToken
    });

  } catch (e) {
    console.log(e);
    res.status(500).json({ error: 'Error al verificar 2FA' });
  }
});

// 👉 RUTA FINAL: si no existe, devolver index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(process.env.PORT, () => {
  console.log(`Servidor escuchando en puerto ${process.env.PORT}`);
});
