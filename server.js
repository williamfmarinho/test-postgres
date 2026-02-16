const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const connectPgSimple = require("connect-pg-simple");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_ROUNDS = Number.parseInt(process.env.BCRYPT_ROUNDS || "10", 10);
const DATABASE_URL =
  process.env.DATABASE_URL || "postgresql://postgres:123@localhost:5432/postgres";

function shouldUseSsl(connectionString) {
  if (!connectionString) return false;

  try {
    const url = new URL(connectionString);
    const sslMode = (url.searchParams.get("sslmode") || "").toLowerCase();
    const isLocalHost =
      url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "::1";

    if (sslMode === "disable" || isLocalHost) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

function getClientLocation(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.trim() !== "") {
    return forwarded.split(",")[0].trim();
  }
  return req.ip || "desconhecido";
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: shouldUseSsl(DATABASE_URL) ? { rejectUnauthorized: false } : false,
});

const PgSessionStore = connectPgSimple(session);

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      role TEXT NOT NULL DEFAULT 'normal',
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'normal'
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS submissions (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      text_value TEXT NOT NULL,
      pix TEXT,
      number_value INTEGER NOT NULL,
      category_value TEXT NOT NULL,
      accepted_terms BOOLEAN NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE submissions
    ADD COLUMN IF NOT EXISTS pix TEXT
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS "registroPonto" (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      horario TIME NOT NULL,
      local TEXT NOT NULL,
      data DATE NOT NULL,
      minuto INTEGER NOT NULL,
      segundo INTEGER NOT NULL,
      created_at TIMESTAMP DEFAULT NOW(),
      UNIQUE (username, data)
    )
  `);

  const admin1Hash = await bcrypt.hash("123", BCRYPT_ROUNDS);
  const admin2Hash = await bcrypt.hash("456", BCRYPT_ROUNDS);

  await pool.query(
    `INSERT INTO users (username, role, password_hash)
     VALUES ($1, $2, $3), ($4, $5, $6)
     ON CONFLICT (username) DO NOTHING`,
    ["admin1", "mestre", admin1Hash, "admin2", "normal", admin2Hash]
  );

  await pool.query(
    `UPDATE users
     SET role = 'mestre'
     WHERE username = 'admin1'`
  );

  await pool.query(
    `UPDATE users
     SET role = 'normal'
     WHERE username = 'admin2'`
  );
}

app.set("trust proxy", 1);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    store: new PgSessionStore({
      pool,
      tableName: "user_sessions",
      createTableIfMissing: true,
    }),
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60 * 8,
      secure: process.env.NODE_ENV === "production",
    },
  })
);

function requireAuth(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

function requireMaster(req, res, next) {
  if (!req.session.user || req.session.user.role !== "mestre") {
    return res.status(403).send("Acesso negado. Apenas usuario mestre pode acessar esta pagina.");
  }
  next();
}

app.get("/", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  return res.redirect("/menu");
});

app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/menu");
  }
  return res.render("login", { error: null });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const userResult = await pool.query(
    "SELECT id, username, role, password_hash FROM users WHERE username = $1",
    [username]
  );

  const user = userResult.rows[0];
  const isValidPassword = user
    ? await bcrypt.compare(password, user.password_hash)
    : false;

  if (!user || !isValidPassword) {
    return res.status(401).render("login", {
      error: "Login ou senha invalidos.",
    });
  }

  req.session.user = { id: user.id, username: user.username, role: user.role };
  return res.redirect("/menu");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.get("/menu", requireAuth, (req, res) => {
  res.render("menu", {
    username: req.session.user.username,
    role: req.session.user.role,
    isMaster: req.session.user.role === "mestre",
  });
});

app.get("/form", requireAuth, async (req, res) => {
  if (req.session.user.role !== "mestre") {
    return res.render("form", {
      username: req.session.user.username,
      submissions: [],
      error: null,
      canViewHistory: false,
    });
  }

  try {
    const { rows } = await pool.query(
      `SELECT id, username, text_value, pix, number_value, category_value, accepted_terms, created_at
       FROM submissions
       ORDER BY created_at DESC
       LIMIT 50`
    );

    return res.render("form", {
      username: req.session.user.username,
      submissions: rows,
      error: null,
      canViewHistory: true,
    });
  } catch (error) {
    return res.status(500).render("form", {
      username: req.session.user.username,
      submissions: [],
      error: "Erro ao carregar dados do banco.",
      canViewHistory: true,
    });
  }
});

app.post("/submit", requireAuth, async (req, res) => {
  const { textValue, pix, numberValue, categoryValue } = req.body;
  const acceptedTerms = req.body.acceptedTerms === "on";

  const parsedNumber = Number.parseInt(numberValue, 10);

  if (!textValue || Number.isNaN(parsedNumber) || !categoryValue) {
    if (req.session.user.role !== "mestre") {
      return res.status(400).render("form", {
        username: req.session.user.username,
        submissions: [],
        error: "Preencha todos os campos obrigatorios.",
        canViewHistory: false,
      });
    }

    const { rows } = await pool.query(
      `SELECT id, username, text_value, pix, number_value, category_value, accepted_terms, created_at
       FROM submissions
       ORDER BY created_at DESC
       LIMIT 50`
    );

    return res.status(400).render("form", {
      username: req.session.user.username,
      submissions: rows,
      error: "Preencha todos os campos obrigatorios.",
      canViewHistory: true,
    });
  }

  await pool.query(
    `INSERT INTO submissions (username, text_value, pix, number_value, category_value, accepted_terms)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [req.session.user.username, textValue, pix || null, parsedNumber, categoryValue, acceptedTerms]
  );

  return res.redirect("/success");
});

app.get("/ponto", requireAuth, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT id, username, horario, local, data, minuto, segundo, created_at
     FROM "registroPonto"
     WHERE username = $1 AND data = CURRENT_DATE
     ORDER BY created_at DESC
     LIMIT 1`,
    [req.session.user.username]
  );

  res.render("ponto", {
    username: req.session.user.username,
    pontoHoje: rows[0] || null,
    message: null,
    error: null,
  });
});

app.post("/ponto", requireAuth, async (req, res) => {
  const local = getClientLocation(req);
  const username = req.session.user.username;

  const insertResult = await pool.query(
    `INSERT INTO "registroPonto" (username, horario, local, data, minuto, segundo)
     VALUES (
       $1,
       CURRENT_TIME,
       $2,
       CURRENT_DATE,
       EXTRACT(MINUTE FROM CURRENT_TIME)::INT,
       EXTRACT(SECOND FROM CURRENT_TIME)::INT
     )
     ON CONFLICT (username, data) DO NOTHING
     RETURNING id, username, horario, local, data, minuto, segundo, created_at`,
    [username, local]
  );

  if (insertResult.rows.length > 0) {
    return res.render("ponto", {
      username,
      pontoHoje: insertResult.rows[0],
      message: "Ponto registrado com sucesso.",
      error: null,
    });
  }

  const existingResult = await pool.query(
    `SELECT id, username, horario, local, data, minuto, segundo, created_at
     FROM "registroPonto"
     WHERE username = $1 AND data = CURRENT_DATE
     ORDER BY created_at DESC
     LIMIT 1`,
    [username]
  );

  return res.status(409).render("ponto", {
    username,
    pontoHoje: existingResult.rows[0] || null,
    message: null,
    error: "Voce ja bateu ponto hoje. O botao fica bloqueado ate o proximo dia.",
  });
});

app.get("/success", requireAuth, (req, res) => {
  res.render("success", { username: req.session.user.username });
});

app.get("/alterar-senha", requireAuth, (req, res) => {
  return res.render("alterar-senha", {
    username: req.session.user.username,
    role: req.session.user.role,
    error: null,
    success: null,
  });
});

app.post("/alterar-senha", requireAuth, async (req, res) => {
  const currentPassword = req.body.currentPassword || "";
  const newPassword = req.body.newPassword || "";
  const confirmPassword = req.body.confirmPassword || "";

  const renderResult = (statusCode, error, success) =>
    res.status(statusCode).render("alterar-senha", {
      username: req.session.user.username,
      role: req.session.user.role,
      error,
      success,
    });

  if (!currentPassword || !newPassword || !confirmPassword) {
    return renderResult(400, "Preencha todos os campos.", null);
  }

  if (newPassword.length < 3) {
    return renderResult(400, "A nova senha deve ter pelo menos 3 caracteres.", null);
  }

  if (newPassword !== confirmPassword) {
    return renderResult(400, "A confirmacao de senha nao confere.", null);
  }

  const userResult = await pool.query(
    "SELECT password_hash FROM users WHERE id = $1",
    [req.session.user.id]
  );
  const dbUser = userResult.rows[0];

  if (!dbUser) {
    return renderResult(404, "Usuario nao encontrado.", null);
  }

  const isCurrentPasswordValid = await bcrypt.compare(
    currentPassword,
    dbUser.password_hash
  );

  if (!isCurrentPasswordValid) {
    return renderResult(401, "Senha atual incorreta.", null);
  }

  const newPasswordHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
  await pool.query("UPDATE users SET password_hash = $1 WHERE id = $2", [
    newPasswordHash,
    req.session.user.id,
  ]);

  return renderResult(200, null, "Senha alterada com sucesso.");
});

app.get("/historico", requireAuth, requireMaster, async (req, res) => {
  const submissionsResult = await pool.query(
    `SELECT id, username, text_value, pix, number_value, category_value, accepted_terms, created_at
     FROM submissions
     ORDER BY created_at DESC
     LIMIT 100`
  );
  const pontoResult = await pool.query(
    `SELECT id, username, horario, local, data, minuto, segundo, created_at
     FROM "registroPonto"
     ORDER BY created_at DESC
     LIMIT 100`
  );

  return res.render("historico", {
    username: req.session.user.username,
    role: req.session.user.role,
    submissions: submissionsResult.rows,
    registrosPonto: pontoResult.rows,
  });
});

app.get("/usuarios/novo", requireAuth, requireMaster, async (req, res) => {
  const usersResult = await pool.query(
    "SELECT id, username, role, created_at FROM users ORDER BY id ASC"
  );

  return res.render("novo-usuario", {
    username: req.session.user.username,
    role: req.session.user.role,
    error: null,
    success: null,
    users: usersResult.rows,
  });
});

app.post("/usuarios/novo", requireAuth, requireMaster, async (req, res) => {
  const username = (req.body.username || "").trim();
  const password = req.body.password || "";

  const renderWithUsers = async (statusCode, error, success) => {
    const usersResult = await pool.query(
      "SELECT id, username, role, created_at FROM users ORDER BY id ASC"
    );
    return res.status(statusCode).render("novo-usuario", {
      username: req.session.user.username,
      role: req.session.user.role,
      error,
      success,
      users: usersResult.rows,
    });
  };

  if (!username || !password) {
    return renderWithUsers(400, "Preencha usuario e senha.", null);
  }

  if (password.length < 3) {
    return renderWithUsers(400, "A senha deve ter pelo menos 3 caracteres.", null);
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  try {
    await pool.query(
      "INSERT INTO users (username, role, password_hash) VALUES ($1, $2, $3)",
      [username, "normal", passwordHash]
    );
  } catch (error) {
    if (error.code === "23505") {
      return renderWithUsers(409, "Este usuario ja existe.", null);
    }
    throw error;
  }

  return renderWithUsers(200, null, `Usuario "${username}" criado com sucesso.`);
});

app.post("/usuarios/excluir/:id", requireAuth, requireMaster, async (req, res) => {
  const userId = Number.parseInt(req.params.id, 10);

  if (Number.isNaN(userId)) {
    return res.status(400).send("ID de usuario invalido.");
  }

  const targetResult = await pool.query(
    "SELECT id, username, role FROM users WHERE id = $1",
    [userId]
  );
  const targetUser = targetResult.rows[0];

  if (!targetUser) {
    return res.status(404).send("Usuario nao encontrado.");
  }

  if (targetUser.username === "admin1" || targetUser.role === "mestre") {
    return res.status(403).send("Usuario mestre nao pode ser excluido.");
  }

  await pool.query("DELETE FROM users WHERE id = $1", [userId]);
  return res.redirect("/usuarios/novo");
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send("Erro interno no servidor.");
});

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Servidor rodando na porta ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Erro ao iniciar banco:", error);
    process.exit(1);
  });
