const { MongoClient } = require("mongodb");

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || "km_db";
const USERS_COLLECTION = process.env.USERS_COLLECTION || "usuarios";

// ===================== A INSERIR NO TOPO DE api/users.js =====================
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || "12", 10);

// opcional: configura transporter caso queira envio de e-mail para reset
let mailTransporter = null;
if (process.env.SMTP_HOST) {
  mailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || "587", 10),
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}
// ========================================================================

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
      return res.end(
        JSON.stringify({ error: "Method Not Allowed. Use POST com action." })
      );
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
          return res.end(
            JSON.stringify({ error: "Corpo inválido. Envie JSON válido." })
          );
        }
      } else {
        body = {};
      }
    }

    const action = body.action;
    if (!action) {
      res.statusCode = 400;
      return res.end(
        JSON.stringify({
          error: "Campo 'action' obrigatório (register | login).",
        })
      );
    }

    const db = await getDb();
    const users = db.collection(USERS_COLLECTION);

    // Recuperação de senha
    // if (action === "recover") {
    //   const { username, email } = body;
    //   if (!username || !email) {
    //     res.statusCode = 400;
    //     return res.end(JSON.stringify({ error: "Preencha usuário e email." }));
    //   }

    //   const usernameNormalized = String(username).trim().toLowerCase();
    //   const user = await users.findOne({ username: usernameNormalized });
    //   if (!user) {
    //     res.statusCode = 404;
    //     return res.end(
    //       JSON.stringify({ error: "Usuário ou email informado está errado." })
    //     );
    //   }

    //   const storedEmail = (user.email || "").trim().toLowerCase();
    //   if (storedEmail !== String(email).trim().toLowerCase()) {
    //     res.statusCode = 404;
    //     return res.end(
    //       JSON.stringify({ error: "Usuário ou email informado está errado." })
    //     );
    //   }

    //   // Retorna a senha
    //   res.statusCode = 200;
    //   return res.end(JSON.stringify({ password: user.password }));
    // }
    // ===================== SUBSTITUIR bloco "recover" =====================
    if (action === "recover") {
      const { username, email } = body;
      if (!username || !email) {
        res.statusCode = 400;
        return res.end(
          JSON.stringify({ error: "Usuário e email são obrigatórios." })
        );
      }

      const usernameNormalized = username.trim().toLowerCase();
      const user = await users.findOne({
        username: usernameNormalized,
        email: email.trim().toLowerCase(),
      });
      if (!user) {
        // responder genérico para evitar enumeração de contas
        res.statusCode = 200;
        return res.end(
          JSON.stringify({
            message:
              "Se houver uma conta com esses dados, um link de recuperação será enviado.",
          })
        );
      }

      // cria token seguro e armazena hash do token
      const token = crypto.randomBytes(32).toString("hex");
      const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
      const expiry = Date.now() + 60 * 60 * 1000; // 1 hora

      await users.updateOne(
        { _id: user._id },
        { $set: { resetTokenHash: tokenHash, resetTokenExpiry: expiry } }
      );

      // envia e-mail com link (se transporter configurado)
      if (mailTransporter && process.env.BASE_URL) {
        const resetLink = `${process.env.BASE_URL.replace(
          /\/$/,
          ""
        )}/reset-password.html?token=${token}&id=${user._id}`;
        try {
          await mailTransporter.sendMail({
            from: process.env.SMTP_FROM || "no-reply@seu-dominio.com",
            to: user.email,
            subject: "Recuperação de senha",
            text: `Solicitação de recuperação de senha. Acesse: ${resetLink}\nO link expira em 1 hora.`,
            html: `Clique <a href="${resetLink}">aqui</a> para redefinir sua senha.`,
          });
        } catch (err) {
          console.error("Erro ao enviar email de recuperação:", err);
          // não retornar erro técnico para o usuário; logar internamente
        }
      }

      // responder sempre com mensagem genérica
      res.statusCode = 200;
      return res.end(
        JSON.stringify({
          message:
            "Se houver uma conta com esses dados, um link de recuperação será enviado.",
        })
      );
    }
    // ========================================================================

    // Registro de novo usuário
    // if (action === "register") {
    //   const { username, email, password } = body;
    //   if (!username || !email || !password) {
    //     res.statusCode = 400;
    //     return res.end(JSON.stringify({ error: "Dados incompletos." }));
    //   }

    //   const usernameNormalized = String(username).trim().toLowerCase();
    //   if (!/^[a-z0-9_\-]+$/.test(usernameNormalized)) {
    //     res.statusCode = 400;
    //     return res.end(JSON.stringify({ error: "Nome de usuário inválido. Use letras, números, '_' ou '-'." }));
    //   }

    //   const existing = await users.findOne({ username: usernameNormalized });
    //   if (existing) {
    //     res.statusCode = 409;
    //     return res.end(JSON.stringify({ error: "Usuário já existe." }));
    //   }

    //   const existingEmail = await users.findOne({ email: email.trim().toLowerCase() });
    //   if (existingEmail) {
    //     res.statusCode = 409;
    //     return res.end(JSON.stringify({ error: "Email já está em uso." }));
    //   }

    //   await users.insertOne({ username: usernameNormalized, email, password });
    //   res.statusCode = 201;
    //   return res.end(JSON.stringify({ message: "Usuário criado." }));
    // }
    // ===================== SUBSTITUIR bloco "register" =====================
    if (action === "register") {
      const { username, email, password } = body;
      if (!username || !email || !password) {
        res.statusCode = 400;
        return res.end(
          JSON.stringify({ error: "Campos obrigatórios ausentes." })
        );
      }

      // validações mínimas de senha (ex.: 8 chars). Ajuste conforme necessidade.
      if (typeof password !== "string" || password.length < 8) {
        res.statusCode = 400;
        return res.end(
          JSON.stringify({ error: "Senha muito curta (mínimo 8 caracteres)." })
        );
      }

      const usernameNormalized = username.trim().toLowerCase();
      const existing = await users.findOne({ username: usernameNormalized });
      if (existing) {
        res.statusCode = 409;
        return res.end(JSON.stringify({ error: "Usuário já existe." }));
      }

      // hash da senha
      const passwordHash = bcrypt.hashSync(password, BCRYPT_ROUNDS);


      const newUser = {
        username: usernameNormalized,
        email: email.trim().toLowerCase(),
        passwordHash,
        createdAt: new Date(),
        failedLoginAttempts: 0,
        lockedUntil: null,
      };

      await users.insertOne(newUser);
      res.statusCode = 201;
      return res.end(
        JSON.stringify({ message: "Usuário registrado com sucesso." })
      );
    }
    // ========================================================================

    // Login de usuário
    // if (action === "login") {
    //   const { username, password } = body;
    //   if (!username || !password) {
    //     res.statusCode = 400;
    //     return res.end(JSON.stringify({ error: "Dados incompletos." }));
    //   }
    //   const usernameNormalized = String(username).trim().toLowerCase();
    //   const user = await users.findOne({ username: usernameNormalized });
    //   if (!user || user.password !== password) {
    //     res.statusCode = 401;
    //     return res.end(JSON.stringify({ error: "Usuário ou senha inválidos." }));
    //   }
    //   res.statusCode = 200;
    //   return res.end(JSON.stringify({ message: "OK" }));
    // }
    // ===================== SUBSTITUIR bloco "login" =====================
    if (action === "login") {
      const { username, password } = body;
      if (!username || !password) {
        res.statusCode = 400;
        return res.end(
          JSON.stringify({ error: "Usuário e senha são obrigatórios." })
        );
      }

      const usernameNormalized = username.trim().toLowerCase();
      const user = await users.findOne({ username: usernameNormalized });

      if (!user) {
        // não revelar se usuário existe
        res.statusCode = 401;
        return res.end(
          JSON.stringify({ error: "Usuário ou senha inválidos." })
        );
      }

      // bloqueio simples: se lockedUntil no futuro, negar
      if (user.lockedUntil && user.lockedUntil > Date.now()) {
        res.statusCode = 429;
        return res.end(
          JSON.stringify({
            error: "Conta temporariamente bloqueada. Tente mais tarde.",
          })
        );
      }

      const match = bcrypt.compareSync(password, user.passwordHash || "");


      if (!match) {
        // incrementar tentativas para lockout
        const attempts = (user.failedLoginAttempts || 0) + 1;
        const update = { failedLoginAttempts: attempts };
        if (attempts >= 5) {
          // exemplo: 5 tentativas -> bloqueia por 15 min
          update.lockedUntil = Date.now() + 15 * 60 * 1000;
          update.failedLoginAttempts = 0;
        }
        await users.updateOne({ _id: user._id }, { $set: update });
        res.statusCode = 401;
        return res.end(
          JSON.stringify({ error: "Usuário ou senha inválidos." })
        );
      }

      // login ok: reset de tentativas
      await users.updateOne(
        { _id: user._id },
        { $set: { failedLoginAttempts: 0, lockedUntil: null } }
      );

      // Aqui retornar token/session conforme seu fluxo. Exemplo simples:
      res.statusCode = 200;
      return res.end(JSON.stringify({ message: "OK" }));
    }
    // ========================================================================

    // ===================== ADICIONAR bloco "reset" =====================
    if (action === "reset") {
      const { id, token, newPassword } = body;
      if (!id || !token || !newPassword) {
        res.statusCode = 400;
        return res.end(
          JSON.stringify({ error: "Dados incompletos para reset." })
        );
      }
      if (typeof newPassword !== "string" || newPassword.length < 8) {
        res.statusCode = 400;
        return res.end(
          JSON.stringify({ error: "Senha muito curta (mínimo 8 caracteres)." })
        );
      }

      const user = await users.findOne({ _id: new ObjectId(id) });
      if (!user || !user.resetTokenHash || !user.resetTokenExpiry) {
        res.statusCode = 400;
        return res.end(
          JSON.stringify({ error: "Token inválido ou expirado." })
        );
      }

      if (user.resetTokenExpiry < Date.now()) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: "Token expirado." }));
      }

      const tokenHash = crypto.createHash("sha256").update(token).digest("hex");
      if (tokenHash !== user.resetTokenHash) {
        res.statusCode = 400;
        return res.end(JSON.stringify({ error: "Token inválido." }));
      }

      // tudo ok: grava nova senha (hash)
      const newHash = bcrypt.hashSync(newPassword, BCRYPT_ROUNDS);

      await users.updateOne(
        { _id: user._id },
        {
          $set: { passwordHash: newHash },
          $unset: { resetTokenHash: "", resetTokenExpiry: "" },
        }
      );

      res.statusCode = 200;
      return res.end(
        JSON.stringify({ message: "Senha redefinida com sucesso." })
      );
    }
    // ========================================================================

    res.statusCode = 400;
    return res.end(JSON.stringify({ error: "Action desconhecida." }));
  } catch (err) {
    res.statusCode = 500;
    const msg = err && err.message ? err.message : "Erro interno";
    return res.end(JSON.stringify({ error: "Erro interno", detail: msg }));
  }
};
