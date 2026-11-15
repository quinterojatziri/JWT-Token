// middlewares: revisan el token antes de dejar pasar a una ruta
require('dotenv').config();
const jwt = require('jsonwebtoken');
const registrarLog = require('./logs');

// la clave sale del .env para que no quede publica en github
const SECRET_KEY = process.env.SECRET_KEY || 'clave_de_prueba_cambiar';
if (!process.env.SECRET_KEY) {
  console.log('Falta SECRET_KEY en el archivo .env, se esta usando una clave de prueba');
}

// el token viene en el header asi: Authorization: Bearer eyJhbG...
function sacarToken(req) {
  const header = req.headers['authorization'];
  if (header && header.startsWith('Bearer ')) {
    return header.split(' ')[1];
  }
  return null;
}

// deja pasar a cualquiera que traiga un token valido
function verificarToken(req, res, next) {
  const token = sacarToken(req);

  if (!token) {
    return res.status(401).json({ ok: false, mensaje: 'Token requerido' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      registrarLog('desconocido', 'TOKEN INVALIDO');
      return res.status(403).json({ ok: false, mensaje: 'Token invalido o expirado' });
    }
    req.usuario = decoded;
    next();
  });
}

// igual que el de arriba pero ademas pide que el rol sea admin.
// con esto arreglamos lo de que se veian los logs con token malo
function soloAdmin(req, res, next) {
  const token = sacarToken(req);

  if (!token) {
    return res.status(401).json({ ok: false, mensaje: 'Token requerido' });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      registrarLog('desconocido', 'TOKEN INVALIDO');
      return res.status(403).json({ ok: false, mensaje: 'Acceso denegado' });
    }

    if (decoded.rol !== 'admin') {
      registrarLog(decoded.usuario, 'ACCESO DENEGADO');
      return res.status(403).json({ ok: false, mensaje: 'Acceso denegado, se necesita ser administrador' });
    }

    req.usuario = decoded;
    next();
  });
}

module.exports = { verificarToken, soloAdmin, SECRET_KEY };
