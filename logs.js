// guarda cada intento de acceso en la tabla logs
// (usuario, fecha, hora y que paso: exitoso, fallido, etc)
const { run } = require('./database');

function registrarLog(usuario, resultado) {
  const ahora = new Date();
  const fecha = ahora.toLocaleDateString('es-MX');
  const hora = ahora.toLocaleTimeString('es-MX');

  run(
    `INSERT INTO logs (usuario, fecha, hora, resultado) VALUES (?, ?, ?, ?)`,
    [usuario || 'desconocido', fecha, hora, resultado]
  ).catch(err => console.log('no se pudo guardar el log:', err.message));
}

module.exports = registrarLog;
