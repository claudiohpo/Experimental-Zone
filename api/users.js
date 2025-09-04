const { MongoClient } = require("mongodb");

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || "km_db";
const USERS_COLLECTION = process.env.USERS_COLLECTION || "usuarios";

// ===================== A INSERIR NO TOPO DE api/users.js =====================
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || "12", 10);

const MAX_LOGIN_ATTEMPTS = parseInt(process.env.MAX_LOGIN_ATTEMPTS || "5", 10);
const LOCK_MINUTES = parseInt(process.env.LOCK_MINUTES || "5", 10);

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

  // debug temporário - LOGS
  console.log("--- /api/users called ---", {
    method: req.method,
    url: req.url,
  });

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
    //apagar depois o console
    console.log("Parsed body:", body);

    // ===================== BLOCO DE LOGIN INSTRUMENTADO (substituir o antigo) =====================
    // ===================== BLOCO DE LOGIN (robusto: conversão de tipos + lock atômico) =====================
    if (action === "login") {
      console.log("[action=login] entrada do bloco login");
      try {
        const { username, password } = body || {};
        console.log("[login] dados recebidos (username exists?):", {
          username: !!username,
          passwordProvided: !!password,
        });

        if (!username || !password) {
          res.statusCode = 400;
          console.log("[login] dados incompletos");
          return res.end(
            JSON.stringify({ error: "Usuário e senha são obrigatórios." })
          );
        }

        const usernameNormalized = String(username).trim().toLowerCase();
        console.log("[login] usernameNormalized:", usernameNormalized);

        // buscar usuário (fresh)
        let user = await users.findOne({ username: usernameNormalized });
        console.log("[login] user encontrado?", !!user);

        if (!user) {
          // não revelar existência do usuário
          res.statusCode = 401;
          return res.end(
            JSON.stringify({ error: "Usuário ou senha inválidos." })
          );
        }

        // --- normaliza lockedUntil para número (milissegundos) para comparações seguras ---
        const lockedUntilTs = (function (v) {
          if (!v) return 0;
          if (typeof v === "number") return v;
          if (v instanceof Date) return v.getTime();
          const n = Number(v);
          return Number.isFinite(n) ? n : 0;
        })(user.lockedUntil);

        // --- auto-unlock: se bloqueado e o tempo já passou, libere e zere contador ---
        if (lockedUntilTs && lockedUntilTs <= Date.now()) {
          await users.updateOne(
            { _id: user._id },
            { $set: { failedLoginAttempts: 0, lockedUntil: null } }
          );
          // atualiza objeto local para refletir
          user.failedLoginAttempts = 0;
          user.lockedUntil = null;
          console.log(
            "[login] conta desbloqueada automaticamente (expiration passed)."
          );
        } else if (lockedUntilTs && lockedUntilTs > Date.now()) {
          // ainda bloqueada: recusa imediatamente
          console.log(
            "[login] tentativa em conta bloqueada até:",
            new Date(lockedUntilTs).toISOString()
          );
          res.statusCode = 429;
          return res.end(
            JSON.stringify({
              error:
                "Conta temporariamente bloqueada. Tente novamente mais tarde.",
              lockedUntil: lockedUntilTs,
            })
          );
        }

        // checa se existe passwordHash no usuário
        if (!user.passwordHash) {
          console.error("[login] usuário sem passwordHash no DB:", {
            userId: user._id,
          });
          res.statusCode = 500;
          return res.end(
            JSON.stringify({ error: "Erro interno (hash ausente)." })
          );
        }

        // compara senha (bcryptjs - síncrono)
        let match = false;
        try {
          match = bcrypt.compareSync(password, user.passwordHash);
        } catch (errCompare) {
          console.error(
            "[login] erro ao comparar hash:",
            errCompare && errCompare.stack ? errCompare.stack : errCompare
          );
          res.statusCode = 500;
          return res.end(
            JSON.stringify({ error: "Erro interno ao validar senha." })
          );
        }

        console.log("[login] resultado compare:", match);

        // if (!match) {
        //   // incremento atômico e retorna documento atualizado
        //   try {
        //     const incRes = await users.findOneAndUpdate(
        //       { _id: user._id },
        //       { $inc: { failedLoginAttempts: 1 } },
        //       { returnDocument: "after" } // driver moderno
        //     );

        //     const attempts =
        //       (incRes.value && incRes.value.failedLoginAttempts) || 0;
        //     console.log("[login] tentativas após increment:", attempts);

        //     if (attempts >= MAX_LOGIN_ATTEMPTS) {
        //       // bloqueio: usa findOneAndUpdate para garantir atomicidade na escrita do lockedUntil
        //       const lockUntil = Date.now() + LOCK_MINUTES * 60 * 1000;
        //       await users.findOneAndUpdate(
        //         { _id: user._id },
        //         { $set: { lockedUntil: lockUntil } },
        //         { returnDocument: "after" }
        //       );
        //       console.log(
        //         "[login] usuário bloqueado até:",
        //         new Date(lockUntil).toISOString()
        //       );
        //       res.statusCode = 429;
        //       return res.end(
        //         JSON.stringify({
        //           error:
        //             "Conta temporariamente bloqueada. Tente novamente mais tarde.",
        //           lockedUntil: lockUntil,
        //         })
        //       );
        //     }

        //     // ainda não atingiu limite, retorno padrão de credenciais inválidas
        //     res.statusCode = 401;
        //     return res.end(
        //       JSON.stringify({ error: "Usuário ou senha inválidos." })
        //     );
        //   } catch (errInc) {
        //     console.error(
        //       "[login] erro ao incrementar tentativas:",
        //       errInc && errInc.stack ? errInc.stack : errInc
        //     );
        //     // fallback: se o incremento falhar, apenas trate como falha de login
        //     res.statusCode = 401;
        //     return res.end(
        //       JSON.stringify({ error: "Usuário ou senha inválidos." })
        //     );
        //   }
        // }
        // substitua o bloco antigo por este
        if (!match) {
          try {
            // 1) incrementa de forma atômica
            await users.updateOne(
              { _id: user._id },
              { $inc: { failedLoginAttempts: 1 } }
            );

            // 2) lê o valor atualizado
            const updated = await users.findOne(
              { _id: user._id },
              { projection: { failedLoginAttempts: 1, lockedUntil: 1 } }
            );

            const attempts = (updated && updated.failedLoginAttempts) || 0;
            console.log(
              "[login] tentativas após increment (via findOne):",
              attempts,
              "lockedUntil(db)=",
              updated && updated.lockedUntil
            );

            if (attempts >= MAX_LOGIN_ATTEMPTS) {
              const lockUntil = Date.now() + LOCK_MINUTES * 60 * 1000;
              // grava lockedUntil (timestamp em ms)
              await users.updateOne(
                { _id: user._id },
                { $set: { lockedUntil: lockUntil } }
              );
              console.log(
                "[login] usuário bloqueado até:",
                new Date(lockUntil).toISOString()
              );

              res.statusCode = 429;
              return res.end(
                JSON.stringify({
                  error: "Conta temporariamente bloqueada.",
                  lockedUntil: lockUntil,
                })
              );
            }

            // ainda não atingiu limite
            res.statusCode = 401;
            return res.end(
              JSON.stringify({ error: "Usuário ou senha inválidos." })
            );
          } catch (errInc) {
            console.error(
              "[login] erro ao incrementar tentativas (fallback):",
              errInc && errInc.stack ? errInc.stack : errInc
            );
            res.statusCode = 401;
            return res.end(
              JSON.stringify({ error: "Usuário ou senha inválidos." })
            );
          }
        }

        // --- senha correta -> reset de tentativas e desbloqueia se necessário ---
        await users.updateOne(
          { _id: user._id },
          { $set: { failedLoginAttempts: 0, lockedUntil: null } }
        );

        // Retorne aqui o que seu app precisa (token/session). Por enquanto:
        res.statusCode = 200;
        console.log("[login] login bem sucedido para:", usernameNormalized);
        return res.end(JSON.stringify({ message: "OK" }));
      } catch (err) {
        console.error(
          "[login] ERRO NÃO TRATADO:",
          err && err.stack ? err.stack : err
        );
        res.statusCode = 500;
        return res.end(
          JSON.stringify({
            error: "Erro interno no login",
            detail: process.env.DEBUG ? err && err.stack : undefined,
          })
        );
      }
    }
    // ===================== FIM BLOCO DE LOGIN INSTRUMENTADO =====================

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
