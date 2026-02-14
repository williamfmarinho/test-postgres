const express = require("express");
const session = require("express-session");
const { Pool } = require("pg");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const USERS = {
  admin1: "123",
  admin2: "456",
};

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

async function initDatabase() {
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
}

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
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

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!USERS[username] || USERS[username] !== password) {
    return res.status(401).render("login", {
      error: "Login ou senha invalidos.",
    });
  }

  req.session.user = { username };
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
