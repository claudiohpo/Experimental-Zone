const { MongoClient, ObjectId } = require("mongodb");

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || "km_db";
const GLOBAL_COLLECTION = process.env.COLLECTION || "usuarios";

let clientPromise = null;

// Função para obter a conexão com o banco de dados
async function getDb() {
  if (!MONGODB_URI) throw new Error("MONGODB_URI não definido");
  if (!clientPromise) {
    const client = new MongoClient(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
    clientPromise = client.connect().then(() => client);
  }
  const client = await clientPromise;
  return client.db(DB_NAME);
}

// Função para limpar o nome de usuário
function sanitizeUsername(u) {
  if (!u) return null;
  const s = String(u).toLowerCase().trim();
  if (!/^[a-z0-9_\-]+$/.test(s)) return null;
  return s;
}

// Função para obter a coleção correta com base no nome de usuário
async function getCollectionForRequest(req) {
  const db = await getDb();
  const headerUser = req.headers ? (req.headers['x-usuario'] || req.headers['x-user'] || req.headers['usuario']) : null;
  const bodyUser = req.body ? req.body.username : null;
  const queryUser = req.query ? req.query.username : null;
  const candidate = headerUser || bodyUser || queryUser || null;
  const username = sanitizeUsername(candidate);
  if (!username) {
    return db.collection(GLOBAL_COLLECTION);
  }
  const collName = `registros_${username}`;
  return db.collection(collName);
}

// ---- Converter data para YYYY-MM-DD
function toYMD(value) {
  if (!value) return new Date().toISOString().slice(0, 10);
  const s = String(value);
  if (s.length >= 10 && s[4] === "-" && s[7] === "-") return s.slice(0, 10);
  try {
    return new Date(s).toISOString().slice(0, 10);
  } catch {
    return new Date().toISOString().slice(0, 10);
  }
}

// função para analisar o corpo da solicitação se req.body não estiver disponível
async function parseBodyFallback(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on && req.on("data", chunk => data += chunk);
    req.on && req.on("end", () => {
      try { resolve(data ? JSON.parse(data) : {}); } catch (e) { resolve({}); }
    });
    req.on && req.on("error", () => resolve({}));
  });
}

// função para processar a solicitação
module.exports = async (req, res) => {
  res.setHeader("Content-Type", "application/json");
  try {
    const collection = await getCollectionForRequest(req);

    if (req.method === "GET") {
      const q = req.query || {};
      if (q.id) {
        try {
          const doc = await collection.findOne({ _id: new ObjectId(q.id) });
          return res.json(doc || null);
        } catch {
          return res.status(400).json({ error: "ID inválido" });
        }
      }
      if (q.ultimo === 'true' || q.ultimo === true) {
        const docs = await collection.find().sort({ data: -1, createdAt: -1 }).limit(1).toArray();
        return res.json(docs[0] || null);
      }
      const docs = await collection.find().sort({ data: -1, createdAt: -1 }).toArray();
      return res.json(docs);
    }

    if (req.method === "POST") {
      const body = req.body || await parseBodyFallback(req);

      const dataStr = toYMD(body.data);
      const kmSaida = (body.kmSaida !== undefined && body.kmSaida !== null) ? Number(body.kmSaida) : null;
      const kmChegada = (body.kmChegada !== undefined && body.kmChegada !== null) ? Number(body.kmChegada) : null;

      const now = new Date();
      const doc = {
        data: dataStr,
        kmSaida,
        kmChegada,
        kmTotal: (kmChegada !== null && kmSaida !== null) ? (Number(kmChegada) - Number(kmSaida)) : null,
        local: body.local || null,              // sempre "local"
        chamado: body.chamado || null,          // <-- novo campo "chamado"
        observacoes: body.observacoes || null,  // sempre "observacoes"
        createdAt: now,
        updatedAt: now
      };

      const result = await collection.insertOne(doc);
      return res.status(201).json({ insertedId: result.insertedId });
    }

    if (req.method === "PUT") {
      const body = req.body || await parseBodyFallback(req);
      if (!body.id) return res.status(400).json({ error: "ID obrigatório" });

      let update = {};
      if (body.data) update.data = toYMD(body.data);
      if (body.kmSaida !== undefined) update.kmSaida = (body.kmSaida !== null && body.kmSaida !== "") ? Number(body.kmSaida) : null;
      if (body.kmChegada !== undefined) update.kmChegada = (body.kmChegada !== null && body.kmChegada !== "") ? Number(body.kmChegada) : null;
      if (body.local !== undefined) update.local = body.local;
      if (body.chamado !== undefined) update.chamado = body.chamado;   // <-- tratar no update também
      if (body.observacoes !== undefined) update.observacoes = body.observacoes;

      if (update.kmChegada !== undefined || update.kmSaida !== undefined) {
        const existing = await collection.findOne({ _id: new ObjectId(body.id) });
        const kmSaida = (update.kmSaida !== undefined) ? update.kmSaida : existing.kmSaida;
        const kmChegada = (update.kmChegada !== undefined) ? update.kmChegada : existing.kmChegada;
        update.kmTotal = (kmChegada !== null && kmSaida !== null) ? Number(kmChegada) - Number(kmSaida) : null;
      }

      update.updatedAt = new Date();

      await collection.updateOne({ _id: new ObjectId(body.id) }, { $set: update });
      return res.json({ message: "Atualizado" });
    }

    if (req.method === "DELETE") {
      const q = req.query || {};
      if (!q.id) return res.status(400).json({ error: "ID obrigatório" });
      try {
        await collection.deleteOne({ _id: new ObjectId(q.id) });
        return res.json({ message: "Registro excluído com sucesso" });
      } catch {
        return res.status(400).json({ error: "ID inválido" });
      }
    }

    res.setHeader("Allow", "GET,POST,PUT,DELETE");
    return res.status(405).json({ error: "Method Not Allowed" });
  } catch (err) {
    console.error("api/km error:", err);
    return res.status(500).json({ error: "Erro interno: " + (err && err.message ? err.message : "unknown") });
  }
};