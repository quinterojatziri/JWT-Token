# Control de Acceso en Red con JWT

Proyecto de control de acceso en red. Maneja los tres conceptos básicos: identificación, autenticación y autorización, y guarda una bitácora con el usuario, la fecha, la hora y el resultado de cada intento de acceso.

## Qué hace
- Registro e inicio de sesión, las contraseñas se guardan cifradas con bcryptjs
- Autenticación con tokens JWT que duran 1 hora
- Dos roles: usuario y administrador (para registrarse como admin hay que poner un código)
- La cuenta se bloquea 5 minutos después de 3 contraseñas incorrectas
- Solo el administrador puede ver los logs, las estadísticas y la lista de usuarios
- El administrador puede cambiar roles, desbloquear y eliminar usuarios
- Modo demostración para probar con token válido, sin token y con token modificado

## Tecnologías
Node.js, Express, SQLite (el que trae Node incluido), bcryptjs, jsonwebtoken, helmet y express-rate-limit.

## Cómo correrlo
1. Tener Node 22.13 o más nuevo e instalar las dependencias con `npm install`
2. Copiar `.env.example` como `.env` y cambiar la SECRET_KEY y el ADMIN_CODE
3. Iniciar con `npm start`
4. Abrir http://localhost:3000 en el navegador

## Rutas
- POST /registro (público)
- POST /login (público)
- GET /panel (cualquier usuario con token)
- GET /logs (admin)
- GET /estadisticas (admin)
- GET /usuarios (admin)
- PUT /usuarios/:id/rol (admin)
- PUT /usuarios/:id/desbloquear (admin)
- DELETE /usuarios/:id (admin)

## Cómo funciona
El usuario inicia sesión, el servidor compara la contraseña con el hash guardado y si coincide genera un token firmado con la SECRET_KEY. Ese token se manda en el header Authorization en cada petición, y los middlewares revisan que sea válido y que el rol sea el correcto antes de dejar pasar. Cada intento queda guardado en la tabla logs.
