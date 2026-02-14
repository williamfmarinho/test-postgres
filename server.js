const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const connectPgSimple = require("connect-pg-simple");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const BCRYPT_ROUNDS = Number.parseInt(process.env.BCRYPT_ROUNDS || "10", 10);

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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: shouldUseSsl(process.env.DATABASE_URL)
    ? { rejectUnauthorized: false }
    : false,
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
      number_value INTEGER NOT NULL,
      category_value TEXT NOT NULL,
      accepted_terms BOOLEAN NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
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

app.get("/", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  return res.redirect("/form");
});

app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/form");
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
  return res.redirect("/form");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.get("/form", requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, username, text_value, number_value, category_value, accepted_terms, created_at
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
  const { textValue, numberValue, categoryValue } = req.body;
  const acceptedTerms = req.body.acceptedTerms === "on";

  const parsedNumber = Number.parseInt(numberValue, 10);

  if (!textValue || Number.isNaN(parsedNumber) || !categoryValue) {
    const { rows } = await pool.query(
      `SELECT id, username, text_value, number_value, category_value, accepted_terms, created_at
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
    `INSERT INTO submissions (username, text_value, number_value, category_value, accepted_terms)
     VALUES ($1, $2, $3, $4, $5)`,
    [req.session.user.username, textValue, parsedNumber, categoryValue, acceptedTerms]
  );

  return res.redirect("/success");
});

app.get("/success", requireAuth, (req, res) => {
  res.render("success", { username: req.session.user.username });
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
