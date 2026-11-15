// servidor principal, aqui estan todas las rutas de la API
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const { run, get, all } = require('./database');
const { verificarToken, soloAdmin, SECRET_KEY } = require('./middleware');
const registrarLog = require('./logs');

// despues de 3 contrasenas malas se bloquea la cuenta 5 minutos
const MAX_INTENTOS = 3;
const MINUTOS_BLOQUEO = 5;

// codigo que hay que escribir para poder registrarse como admin
const ADMIN_CODE = process.env.ADMIN_CODE || 'ADMIN2026';

const app = express();
app.use(helmet({ contentSecurityPolicy: false })); // el csp lo quitamos porque el html usa scripts dentro del mismo archivo
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

// para que no se puedan hacer cientos de intentos seguidos al login
const limiteLogin = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { ok: false, mensaje: 'Demasiados intentos, espera un rato' }
});

// ---------- registro ----------
app.post('/registro', async (req, res) => {
  try {
    const { usuario, password, rol, codigoAdmin } = req.body;

    if (!/^[A-Za-z0-9_.-]{3,20}$/.test(usuario || '')) {
      return res.status(400).json({ ok: false, mensaje: 'El usuario debe tener de 3 a 20 caracteres (letras, numeros, guion o punto)' });
    }
    if (!password || password.length < 8) {
      return res.status(400).json({ ok: false, mensaje: 'La contraseña debe tener minimo 8 caracteres' });
    }

    // si mandan cualquier cosa rara en rol se queda como usuario normal
    const rolFinal = rol === 'admin' ? 'admin' : 'usuario';

    if (rolFinal === 'admin' && codigoAdmin !== ADMIN_CODE) {
      return res.status(403).json({ ok: false, mensaje: 'Codigo de administrador incorrecto' });
    }

    const hash = await bcrypt.hash(password, 10);
    await run(
      `INSERT INTO usuarios (usuario, password, rol) VALUES (?, ?, ?)`,
      [usuario, hash, rolFinal]
    );

    registrarLog(usuario, 'REGISTRO (' + rolFinal + ')');
    res.status(201).json({ ok: true, mensaje: 'Usuario registrado con rol: ' + rolFinal });

  } catch (err) {
    // el campo usuario es UNIQUE, si se repite sqlite marca este error
    if (String(err.message).includes('UNIQUE')) {
      return res.status(409).json({ ok: false, mensaje: 'Ese usuario ya existe' });
    }
    res.status(500).json({ ok: false, mensaje: 'Error en el servidor' });
  }
});

// ---------- login ----------
app.post('/login', limiteLogin, async (req, res) => {
  try {
    const { usuario, password } = req.body;
    const user = await get(`SELECT * FROM usuarios WHERE usuario = ?`, [usuario]);

    // mismo mensaje si no existe o si la contraseña esta mal, para no dar pistas
    if (!user) {
      registrarLog(usuario, 'FALLIDO');
      return res.status(401).json({ ok: false, mensaje: 'Usuario o contraseña incorrectos' });
    }

    // primero checamos si la cuenta sigue bloqueada
    if (user.bloqueado_hasta > Date.now()) {
      const faltan = Math.ceil((user.bloqueado_hasta - Date.now()) / 60000);
      registrarLog(usuario, 'BLOQUEADO');
      return res.status(423).json({ ok: false, mensaje: 'Cuenta bloqueada, intenta en ' + faltan + ' minuto(s)' });
    }

    const valido = await bcrypt.compare(password || '', user.password);

    if (!valido) {
      const intentos = (user.intentos || 0) + 1;

      if (intentos >= MAX_INTENTOS) {
        const hasta = Date.now() + MINUTOS_BLOQUEO * 60000;
        await run(`UPDATE usuarios SET intentos = 0, bloqueado_hasta = ? WHERE id = ?`, [hasta, user.id]);
        registrarLog(usuario, 'BLOQUEADO');
        return res.status(423).json({ ok: false, mensaje: 'Demasiados intentos, cuenta bloqueada ' + MINUTOS_BLOQUEO + ' minutos' });
      }

      await run(`UPDATE usuarios SET intentos = ? WHERE id = ?`, [intentos, user.id]);
      registrarLog(usuario, 'FALLIDO');
      return res.status(401).json({ ok: false, mensaje: 'Usuario o contraseña incorrectos (intento ' + intentos + ' de ' + MAX_INTENTOS + ')' });
    }

    // si entro bien se reinician los intentos
    await run(`UPDATE usuarios SET intentos = 0, bloqueado_hasta = 0 WHERE id = ?`, [user.id]);

    const token = jwt.sign(
      { id: user.id, usuario: user.usuario, rol: user.rol },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    registrarLog(usuario, 'EXITOSO');
    res.json({ ok: true, mensaje: 'Inicio de sesion exitoso', token });

  } catch (err) {
    res.status(500).json({ ok: false, mensaje: 'Error en el servidor' });
  }
});

// ---------- ruta protegida (cualquier usuario con token) ----------
app.get('/panel', verificarToken, (req, res) => {
  res.json({ ok: true, mensaje: 'Acceso autorizado', usuario: req.usuario });
});

// ---------- rutas solo para admin ----------

// bitacora, se puede filtrar por usuario o por resultado
app.get('/logs', soloAdmin, async (req, res) => {
  try {
    const { usuario, resultado } = req.query;
    let sql = `SELECT usuario, fecha, hora, resultado FROM logs WHERE 1=1`;
    const params = [];

    if (usuario) {
      sql += ` AND usuario LIKE ?`;
      params.push('%' + usuario + '%');
    }
    if (resultado) {
      sql += ` AND resultado LIKE ?`;
      params.push(resultado + '%');
    }

    sql += ` ORDER BY id DESC LIMIT 300`;
    res.json(await all(sql, params));

  } catch (err) {
    res.status(500).json({ ok: false, mensaje: 'Error al obtener los logs' });
  }
});

// numeros para las tarjetas del inicio
app.get('/estadisticas', soloAdmin, async (req, res) => {
  try {
    const contar = async (donde) => (await get(`SELECT COUNT(*) AS c FROM logs ${donde}`)).c;

    res.json({
      total: await contar(''),
      exitosos: await contar(`WHERE resultado = 'EXITOSO'`),
      fallidos: await contar(`WHERE resultado = 'FALLIDO'`),
      bloqueos: await contar(`WHERE resultado = 'BLOQUEADO'`),
      usuarios: (await get(`SELECT COUNT(*) AS c FROM usuarios`)).c,
      ultimo: await get(`SELECT usuario, fecha, hora FROM logs WHERE resultado = 'EXITOSO' ORDER BY id DESC LIMIT 1`)
    });
  } catch (err) {
    res.status(500).json({ ok: false, mensaje: 'Error en el servidor' });
  }
});

app.get('/usuarios', soloAdmin, async (req, res) => {
  try {
    res.json(await all(`SELECT id, usuario, rol, bloqueado_hasta FROM usuarios ORDER BY id`));
  } catch (err) {
    res.status(500).json({ ok: false, mensaje: 'Error en el servidor' });
  }
});

app.put('/usuarios/:id/rol', soloAdmin, async (req, res) => {
  const { rol } = req.body;

  if (rol !== 'admin' && rol !== 'usuario') {
    return res.status(400).json({ ok: false, mensaje: 'Rol invalido' });
  }
  // para que un admin no se quite a si mismo el permiso por accidente
  if (Number(req.params.id) === req.usuario.id) {
    return res.status(400).json({ ok: false, mensaje: 'No puedes cambiar tu propio rol' });
  }

  await run(`UPDATE usuarios SET rol = ? WHERE id = ?`, [rol, req.params.id]);
  registrarLog(req.usuario.usuario, 'CAMBIO DE ROL (id ' + req.params.id + ' a ' + rol + ')');
  res.json({ ok: true, mensaje: 'Rol actualizado' });
});

app.put('/usuarios/:id/desbloquear', soloAdmin, async (req, res) => {
  await run(`UPDATE usuarios SET intentos = 0, bloqueado_hasta = 0 WHERE id = ?`, [req.params.id]);
  registrarLog(req.usuario.usuario, 'DESBLOQUEO (id ' + req.params.id + ')');
  res.json({ ok: true, mensaje: 'Usuario desbloqueado' });
});

app.delete('/usuarios/:id', soloAdmin, async (req, res) => {
  if (Number(req.params.id) === req.usuario.id) {
    return res.status(400).json({ ok: false, mensaje: 'No puedes eliminar tu propia cuenta' });
  }

  await run(`DELETE FROM usuarios WHERE id = ?`, [req.params.id]);
  registrarLog(req.usuario.usuario, 'USUARIO ELIMINADO (id ' + req.params.id + ')');
  res.json({ ok: true, mensaje: 'Usuario eliminado' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('Servidor corriendo en http://localhost:' + PORT);
});
