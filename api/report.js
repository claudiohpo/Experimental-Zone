const { MongoClient } = require("mongodb");

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || "km_db";
const GLOBAL_COLLECTION = process.env.COLLECTION || "usuarios";

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

// Função para limpar o nome de usuário
function sanitizeUsername(u) {
  if (!u) return null;
  const s = String(u).toLowerCase().trim();
  if (!/^[a-z0-9_\-]+$/.test(s)) return null;
  return s;
}

// Função para obter a coleção correta com base no cabeçalho da requisição
async function getCollectionForRequest(req) { 
  const db = await getDb();
  const headerUser = req.headers ? (req.headers['x-usuario'] || req.headers['x-user'] || req.headers['usuario']) : null;
  const username = sanitizeUsername(headerUser);
  if (!username) {
    return db.collection(GLOBAL_COLLECTION);
  }
  const collName = `registros_${username}`;
  return db.collection(collName);
}

function toCsv(rows, headers) {
  const esc = (v) => `"${(v || "").toString().replace(/"/g, '""')}"`;
  const lines = [headers.join(",")];
  for (const r of rows) {
    lines.push(headers.map((h) => esc(r[h])).join(","));
  }
  return lines.join("\n");
}

// Função para processar a solicitação
module.exports = async (req, res) => {
  try {
    if (req.method !== "GET") return res.status(405).end("Method Not Allowed");

    const col = await getCollectionForRequest(req);  // Agora dinâmico, como em api/km.js
    const { from, to, format, local } = req.query;
    const filter = {};
    
    // Filtro por data
    if (from || to) {
      filter.data = {};
      if (from) filter.data.$gte = from;
      if (to) filter.data.$lte = to;
    }
    
    // Filtro por local
    if (local) {
      filter.local = { $regex: local, $options: "i" }; // Busca case-insensitive
    }
    
    const docs = await col.find(filter).sort({ data: 1 }).toArray();

    if ((format || "csv").toLowerCase() === "csv") {
      const headers = [
        "data",
        "chamado",
        "local",
        "kmSaida",
        "kmChegada",
        "kmTotal",
        "observacoes",
        "criadoEm",
      ];
      const rows = docs.map((d) => ({
        data: d.data || "",
        chamado: d.chamado || "",
        local: d.local || "",
        kmSaida: d.kmSaida ?? "",
        kmChegada: d.kmChegada ?? "",
        kmTotal: d.kmTotal ?? (d.kmChegada - d.kmSaida),
        observacoes: d.observacoes || "",
        criadoEm: d.createdAt
          ? new Date(d.createdAt).toISOString()
          : d.criadoEm || "",
      }));
      const csv = toCsv(rows, headers);
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader(
        "Content-Disposition",
        "attachment; filename=relatorio_km.csv"
      );
      return res.send(csv);
    } else {
      return res.json(docs);
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro interno" });
  }
};