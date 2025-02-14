// server.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Configuración de middlewares
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({
  secret: 'mi_secreto_super_secreto', // Cambia este valor en producción
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false } // Usa true en HTTPS
}));

// Crear un pool de conexiones en lugar de una única conexión
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'miguel_de_cervantes',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// -----------------------------
// Creación de Tablas en la Base de Datos
// -----------------------------

// Tabla "usuarios"
const createUsuariosTable = `
CREATE TABLE IF NOT EXISTS usuarios (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  role VARCHAR(20) NOT NULL DEFAULT 'estudiante',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`;
pool.query(createUsuariosTable, (err, result) => {
  if (err) console.error('Error al crear la tabla "usuarios":', err);
  else console.log('Tabla "usuarios" lista.');
});

// Tabla "announcements" (con columna "image")
const createAnnouncementsTable = `
CREATE TABLE IF NOT EXISTS announcements (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  content TEXT NOT NULL,
  image VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`;
pool.query(createAnnouncementsTable, (err, result) => {
  if (err) console.error('Error al crear la tabla "announcements":', err);
  else console.log('Tabla "announcements" lista.');
});

// Tabla "tasks" (para tareas)
const createTasksTable = `
CREATE TABLE IF NOT EXISTS tasks (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL,
  due_date DATE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`;
pool.query(createTasksTable, (err, result) => {
  if (err) console.error('Error al crear la tabla "tasks":', err);
  else console.log('Tabla "tasks" lista.');
});

// Tabla "teacher_info" (para notas y trabajos)
const createTeacherInfoTable = `
CREATE TABLE IF NOT EXISTS teacher_info (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  description TEXT NOT NULL,
  type ENUM('nota','trabajo') NOT NULL,
  student_id INT,
  due_date DATE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`;
pool.query(createTeacherInfoTable, (err, result) => {
  if (err) console.error('Error al crear la tabla "teacher_info":', err);
  else console.log('Tabla "teacher_info" lista.');
});

// -----------------------------
// Middleware de Autenticación y Roles
// -----------------------------
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Usuario no autenticado' });
}

function isAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'admin') return next();
  return res.status(403).json({ error: 'Acceso restringido, solo administradores' });
}

function isTeacher(req, res, next) {
  if (req.session && req.session.user && req.session.user.role === 'profesor') return next();
  return res.status(403).json({ error: 'Acceso restringido, solo profesores' });
}

// -----------------------------
// Endpoints de Autenticación y Registro
// -----------------------------
app.post('/api/register', (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos requeridos' });
  let userRole = 'estudiante';
  if (req.session && req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'profesor') && role) {
    userRole = role;
  }
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) return res.status(500).json({ error: 'Error al encriptar la contraseña' });
    const query = 'INSERT INTO usuarios (username, password, role) VALUES (?, ?, ?)';
    pool.query(query, [username, hashedPassword, userRole], (err, result) => {
      if (err) {
        console.error('Error al registrar usuario:', err);
        return res.status(500).json({ error: 'Error al registrar usuario' });
      }
      res.status(201).json({ message: 'Usuario registrado exitosamente' });
    });
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Faltan datos requeridos' });
  const query = 'SELECT * FROM usuarios WHERE username = ?';
  pool.query(query, [username], (err, results) => {
    if (err) {
      console.error('Error al buscar usuario:', err);
      return res.status(500).json({ error: 'Error en el servidor' });
    }
    if (results.length === 0) return res.status(401).json({ error: 'Credenciales inválidas' });
    const user = results[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error('Error al comparar contraseñas:', err);
        return res.status(500).json({ error: 'Error en el servidor' });
      }
      if (!isMatch) return res.status(401).json({ error: 'Credenciales inválidas' });
      req.session.user = { id: user.id, username: user.username, role: user.role };
      res.json({ message: 'Inicio de sesión exitoso', role: user.role });
    });
  });
});

app.get('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Error al cerrar sesión' });
    res.json({ message: 'Sesión cerrada correctamente' });
  });
});

// -----------------------------
// Endpoints para Anuncios
// -----------------------------
app.get('/api/announcements', (req, res) => {
  const query = 'SELECT * FROM announcements ORDER BY created_at DESC';
  pool.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener anuncios:', err);
      return res.status(500).json({ error: 'Error al obtener anuncios' });
    }
    res.json(results);
  });
});

app.post('/api/announcements', isAuthenticated, isAdmin, (req, res) => {
  const { title, content, image } = req.body;
  if (!title || !content) return res.status(400).json({ error: 'Faltan datos requeridos para el anuncio' });
  const query = 'INSERT INTO announcements (title, content, image) VALUES (?, ?, ?)';
  pool.query(query, [title, content, image || null], (err, result) => {
    if (err) {
      console.error('Error al crear anuncio:', err);
      return res.status(500).json({ error: 'Error al crear anuncio' });
    }
    res.status(201).json({ message: 'Anuncio publicado exitosamente' });
  });
});

app.put('/api/announcements/:id', isAuthenticated, isAdmin, (req, res) => {
  const announcementId = parseInt(req.params.id, 10);
  const { title, content, image } = req.body;
  if (isNaN(announcementId)) return res.status(400).json({ error: 'El ID del anuncio no es válido' });
  if (!title || !content) return res.status(400).json({ error: 'Faltan datos para actualizar el anuncio' });
  const query = 'UPDATE announcements SET title = ?, content = ?, image = ? WHERE id = ?';
  pool.query(query, [title, content, image || null, announcementId], (err, result) => {
    if (err) {
      console.error('Error al actualizar anuncio:', err);
      return res.status(500).json({ error: 'Error al actualizar anuncio', details: err.message });
    }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Anuncio no encontrado' });
    res.json({ message: 'Anuncio actualizado exitosamente' });
  });
});

app.delete('/api/announcements/:id', isAuthenticated, isAdmin, (req, res) => {
  const announcementId = parseInt(req.params.id, 10);
  if (isNaN(announcementId)) return res.status(400).json({ error: 'El ID del anuncio no es válido' });
  const query = 'DELETE FROM announcements WHERE id = ?';
  pool.query(query, [announcementId], (err, result) => {
    if (err) {
      console.error('Error al borrar anuncio:', err);
      return res.status(500).json({ error: 'Error al borrar anuncio', details: err.message });
    }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Anuncio no encontrado' });
    res.json({ message: 'Anuncio borrado exitosamente' });
  });
});

// -----------------------------
// Endpoints para Usuarios (Listar y Borrar)
// -----------------------------
app.get('/api/users', isAuthenticated, isAdmin, (req, res) => {
  const query = 'SELECT * FROM usuarios ORDER BY created_at DESC';
  pool.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener usuarios:', err);
      return res.status(500).json({ error: 'Error al obtener usuarios', details: err.message });
    }
    res.json(results);
  });
});

app.delete('/api/users/:id', isAuthenticated, isAdmin, (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId)) return res.status(400).json({ error: 'El ID del usuario no es válido' });
  if (req.session.user.id === userId) return res.status(400).json({ error: 'No puedes borrar tu propio usuario' });
  const query = 'DELETE FROM usuarios WHERE id = ?';
  pool.query(query, [userId], (err, result) => {
    if (err) {
      console.error('Error al borrar usuario:', err);
      return res.status(500).json({ error: 'Error al borrar usuario', details: err.message });
    }
    if (result.affectedRows === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ message: 'Usuario borrado exitosamente' });
  });
});

// -----------------------------
// Endpoints para Tareas (Subidas por Profesores)
// -----------------------------
app.get('/api/tasks', isAuthenticated, (req, res) => {
  let query = 'SELECT * FROM tasks';
  let params = [];
  if (req.query.due_date) {
    query += ' WHERE due_date = ?';
    params.push(req.query.due_date);
  }
  query += ' ORDER BY due_date ASC';
  pool.query(query, params, (err, results) => {
    if(err) {
      console.error('Error al obtener tareas:', err);
      return res.status(500).json({ error: 'Error al obtener tareas' });
    }
    res.json(results);
  });
});

// Solo profesores pueden subir tareas
app.post('/api/tasks', isAuthenticated, isTeacher, (req, res) => {
  const { title, description, due_date } = req.body;
  if (!title || !description) return res.status(400).json({ error: 'Faltan datos para la tarea' });
  const query = 'INSERT INTO tasks (title, description, due_date) VALUES (?, ?, ?)';
  pool.query(query, [title, description, due_date || null], (err, result) => {
    if (err) {
      console.error('Error al crear tarea:', err);
      return res.status(500).json({ error: 'Error al crear tarea' });
    }
    res.status(201).json({ message: 'Tarea creada exitosamente' });
  });
});

// -----------------------------
// Endpoints para Notas (teacher_info de tipo 'nota')
// -----------------------------
app.get('/api/notes', isAuthenticated, (req, res) => {
  const query = "SELECT * FROM teacher_info WHERE type = 'nota' ORDER BY created_at DESC";
  pool.query(query, (err, results) => {
    if(err) {
      console.error('Error al obtener notas:', err);
      return res.status(500).json({ error: 'Error al obtener notas', details: err.message });
    }
    res.json(results);
  });
});

// Endpoint para subir información de profesor (notas y trabajos), restringido a profesores
app.post('/api/teacher_info', isAuthenticated, isTeacher, (req, res) => {
  const { title, description, type, student_id, due_date } = req.body;
  if (!title || !description || !type) return res.status(400).json({ error: 'Faltan datos para la información de profesor' });
  if (type !== 'nota' && type !== 'trabajo') return res.status(400).json({ error: 'El tipo debe ser "nota" o "trabajo"' });
  const query = 'INSERT INTO teacher_info (title, description, type, student_id, due_date) VALUES (?, ?, ?, ?, ?)';
  pool.query(query, [title, description, type, student_id || null, due_date || null], (err, result) => {
    if (err) {
      console.error('Error al subir información de profesor:', err);
      return res.status(500).json({ error: 'Error al subir información de profesor', details: err.message });
    }
    res.status(201).json({ message: 'Información de profesor subida exitosamente' });
  });
});

// -----------------------------
// Servir Archivos Estáticos
// -----------------------------
app.use(express.static(path.join(__dirname, 'public')));

// Iniciar el Servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en el puerto ${port}`);
});
