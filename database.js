// aqui se crea la conexion a sqlite y las tablas.
// usamos node:sqlite que ya viene incluido en node, asi no hay que instalar ni compilar nada.
// el archivo database.db se genera solo la primera vez que corre el servidor
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync('./database.db');

// estas tres funciones las dejamos como promesas (async) para usar await en el server
const run = async (sql, params = []) => db.prepare(sql).run(...params);
const get = async (sql, params = []) => db.prepare(sql).get(...params);
const all = async (sql, params = []) => db.prepare(sql).all(...params);

// tabla de usuarios, intentos y bloqueado_hasta sirven para el bloqueo por contrasena mala
db.exec(`CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario TEXT UNIQUE,
  password TEXT,
  rol TEXT DEFAULT 'usuario',
  intentos INTEGER DEFAULT 0,
  bloqueado_hasta INTEGER DEFAULT 0
)`);

// la bitacora de accesos
db.exec(`CREATE TABLE IF NOT EXISTS logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario TEXT,
  fecha TEXT,
  hora TEXT,
  resultado TEXT
)`);

// si ya tenian una base vieja sin estas columnas se las agregamos,
// si ya existen marca error y simplemente lo ignoramos
try { db.exec('ALTER TABLE usuarios ADD COLUMN intentos INTEGER DEFAULT 0'); } catch (e) {}
try { db.exec('ALTER TABLE usuarios ADD COLUMN bloqueado_hasta INTEGER DEFAULT 0'); } catch (e) {}

module.exports = { db, run, get, all };
