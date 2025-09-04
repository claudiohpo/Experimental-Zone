const { MongoClient } = require("mongodb");

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || "km_db";
const USERS_COLLECTION = process.env.USERS_COLLECTION || "usuarios";

let clientPromise = null;

// Função para obter a conexão com o banco de dados
async function getDb() {
  if (!MONGODB_URI) throw new Error("MONGODB_URI não definido");
  if (!clientPromise) {
    const client = new MongoClient(MONGODB_URI);
    clientPromise = client.connect().then(() => client);
  }
  const client = await clientPromise;
  return client.db(DB_NAME);
}

// Função para ler o corpo da requisição em ambientes sem suporte a req.body
async function readRawBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on && req.on("data", (chunk) => (data += chunk));
    req.on && req.on("end", () => resolve(data || null));
    req.on && req.on("error", () => resolve(null));
  });
}

// Função para processar a solicitação
module.exports = async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");

  try {
    if (req.method !== "POST") {
      res.statusCode = 405;
      return res.end(JSON.stringify({ error: "Method Not Allowed. Use POST com action." }));
    }

    // prefirir req.body se disponível; senão leia raw e parse
    let body = req.body && Object.keys(req.body).length ? req.body : null;
    if (!body) {
      const raw = await readRawBody(req);
      if (raw) {
        try {
          body = JSON.parse(raw);
        } catch (e) {
          res.statusCode = 400;
          return res.end(JSON.stringify({ error: "Corpo inválido. Envie JSON válido." }));
        }
      } else {
        body = {};
      }
    }

    const action = body.action;
    if (!action) {
      res.statusCode = 400;
      return res.end(JSON.stringify({ error: "Campo 'action' obrigatório (register | login)." }));
    }

    const db = await getDb();
    const users = db.collection(USERS_COLLECTION);

    // Recuperação de senha
    if (action === "recover") {
      const { username, email } = body;
      if (!username || !email) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: "Preencha usuário e email." }));
      }

      const usernameNormalized = String(username).trim().toLowerCase();
      const user = await users.findOne({ username: usernameNormalized });
      if (!user) {
        res.statusCode = 404;
        return res.end(JSON.stringify({ error: "Usuário ou email informado está errado." }));
      }

      const storedEmail = (user.email || "").trim().toLowerCase();
      if (storedEmail !== String(email).trim().toLowerCase()) {
        res.statusCode = 404;
        return res.end(JSON.stringify({ error: "Usuário ou email informado está errado." }));
      }

      // Retorna a senha
      res.statusCode = 200;
      return res.end(JSON.stringify({ password: user.password }));
    }

    // Registro de novo usuário
    if (action === "register") {
      const { username, email, password } = body;
      if (!username || !email || !password) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: "Dados incompletos." }));
      }

      const usernameNormalized = String(username).trim().toLowerCase();
      if (!/^[a-z0-9_\-]+$/.test(usernameNormalized)) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: "Nome de usuário inválido. Use letras, números, '_' ou '-'." }));
      }

      const existing = await users.findOne({ username: usernameNormalized });
      if (existing) {
        res.statusCode = 409;
        return res.end(JSON.stringify({ error: "Usuário já existe." }));
      }

      const existingEmail = await users.findOne({ email: email.trim().toLowerCase() });
      if (existingEmail) {
        res.statusCode = 409;
        return res.end(JSON.stringify({ error: "Email já está em uso." }));
      }

      await users.insertOne({ username: usernameNormalized, email, password });
      res.statusCode = 201;
      return res.end(JSON.stringify({ message: "Usuário criado." }));
    }

    if (action === "login") {
      const { username, password } = body;
      if (!username || !password) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: "Dados incompletos." }));
      }
      const usernameNormalized = String(username).trim().toLowerCase();
      const user = await users.findOne({ username: usernameNormalized });
      if (!user || user.password !== password) {
        res.statusCode = 401;
        return res.end(JSON.stringify({ error: "Usuário ou senha inválidos." }));
      }
      res.statusCode = 200;
      return res.end(JSON.stringify({ message: "OK" }));
    }

    res.statusCode = 400;
    return res.end(JSON.stringify({ error: "Action desconhecida." }));
  } catch (err) {
    res.statusCode = 500;
    const msg = (err && err.message) ? err.message : "Erro interno";
    return res.end(JSON.stringify({ error: "Erro interno", detail: msg }));
  }
};