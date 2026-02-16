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
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
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
    `INSERT INTO users (username, password_hash)
     VALUES ($1, $2), ($3, $4)
     ON CONFLICT (username) DO UPDATE
     SET password_hash = EXCLUDED.password_hash`,
    ["admin1", admin1Hash, "admin2", admin2Hash]
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

function requireAdmin1(req, res, next) {
  if (!req.session.user || req.session.user.username !== "admin1") {
    return res.status(403).send("Acesso negado. Apenas admin1 pode acessar esta pagina.");
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
    "SELECT id, username, password_hash FROM users WHERE username = $1",
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

  req.session.user = { id: user.id, username: user.username };
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
    isAdmin1: req.session.user.username === "admin1",
  });
});

app.get("/form", requireAuth, async (req, res) => {
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
    });
  } catch (error) {
    return res.status(500).render("form", {
      username: req.session.user.username,
      submissions: [],
      error: "Erro ao carregar dados do banco.",
    });
  }
});

app.post("/submit", requireAuth, async (req, res) => {
  const { textValue, pix, numberValue, categoryValue } = req.body;
  const acceptedTerms = req.body.acceptedTerms === "on";

  const parsedNumber = Number.parseInt(numberValue, 10);

  if (!textValue || Number.isNaN(parsedNumber) || !categoryValue) {
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

app.get("/usuarios/novo", requireAuth, requireAdmin1, (req, res) => {
  return res.render("novo-usuario", {
    username: req.session.user.username,
    error: null,
    success: null,
  });
});

app.post("/usuarios/novo", requireAuth, requireAdmin1, async (req, res) => {
  const username = (req.body.username || "").trim();
  const password = req.body.password || "";

  if (!username || !password) {
    return res.status(400).render("novo-usuario", {
      username: req.session.user.username,
      error: "Preencha usuario e senha.",
      success: null,
    });
  }

  if (password.length < 3) {
    return res.status(400).render("novo-usuario", {
      username: req.session.user.username,
      error: "A senha deve ter pelo menos 3 caracteres.",
      success: null,
    });
  }

  const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

  try {
    await pool.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2)",
      [username, passwordHash]
    );
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).render("novo-usuario", {
        username: req.session.user.username,
        error: "Este usuario ja existe.",
        success: null,
      });
    }
    throw error;
  }

  return res.render("novo-usuario", {
    username: req.session.user.username,
    error: null,
    success: `Usuario "${username}" criado com sucesso.`,
  });
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
