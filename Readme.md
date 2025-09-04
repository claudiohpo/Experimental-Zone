# 🚗 Registro de KM Rodados

Um sistema completo para controle de quilometragem veicular, permitindo o registro de deslocamentos, geração de relatórios e manutenção de registros.

## ✨ Funcionalidades

- 📝 Registro de deslocamentos com dados completos (data, local, KM de saída/chegada)
- 📊 Geração de relatórios em CSV e XLSX
- ✏️ Edição e exclusão de registros existentes
- 🔍 Sistema de filtros por data e local
- 📱 Interface responsiva para mobile e desktop
- 💾 Armazenamento em MongoDB
- 🌐 Deploy pronto para Vercel

## 🛠️ Tecnologias Utilizadas

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)
![Vercel](https://img.shields.io/badge/Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)

## 📦 Estrutura do Projeto

```
📁 projeto-km/
├── 📁 api/                # Funções serverless
│   ├── km.js                 # API principal (CRUD)
│   └── report.js             # Geração de relatórios
├── 📁 css/                # Pasta contendo Estilos 
│   ├── main.css              # Estilos principais 
│   └── management.css        # Estilos da página de gestão 
├── 📁 js/                 # Scripts frontend (agrupa JS para separar do backend em /api)
│   ├── main.js               # Script principal 
│   └── management.js         # Script da página de gestão 
├── 📄 index.html          # Página principal 
├── 📄 management.html     # Página de gestão 
├── 📄 vercel.json         # Configuração do Vercel
└── 📄 package.json        # Dependências do projeto

```

## 🚀 Como Usar

### Pré-requisitos

- Node.js instalado
- Conta no MongoDB Atlas ou instância local
- Conta no Vercel (para deploy)

### Instalação Local

1. Clone o repositório:
```bash
git clone <url-do-repositorio>
cd projeto-km
```

2. Instale as dependências:
```bash
npm install
```

3. Configure as variáveis de ambiente:
```bash
cp .env.example .env
```
Edite o arquivo `.env` com suas credenciais do MongoDB.

4. Execute localmente:
```bash
npm run dev
```

### Deploy na Vercel

1. Faça o fork deste repositório
2. Conecte sua conta do Vercel ao repositório
3. Configure as variáveis de ambiente no painel da Vercel
4. Deploy automático! 🎉

## 🔧 Configuração

### Variáveis de Ambiente

| Variável | Descrição | Exemplo |
|----------|-----------|---------|
| MONGODB_URI | URI de conexão com MongoDB | `mongodb+srv://user:pass@cluster...` |
| DB_NAME | Nome do banco de dados | `km_db` |
| COLLECTION | Nome da coleção | `km_registros` |

### Estrutura dos Dados

Cada registro possui:
```json
{
  "data": "2023-12-01",
  "chamado": "12345",
  "local": "São Paulo - Cliente X",
  "kmSaida": 15000,
  "kmChegada": 15050,
  "kmTotal": 50,
  "observacoes": "Visita técnica",
  "createdAt": "2023-12-01T10:00:00.000Z"
}
```

## 📋 API Endpoints

### GET `/api/km`
Retorna todos os registros ou um registro específico com `?id=`

### POST `/api/km`
Cria um novo registro

### PUT `/api/km?id=`
Atualiza um registro existente

### DELETE `/api/km?id=`
Exclui um registro

### GET `/api/report?format=csv`
Gera relatório em CSV dos registros

## 👨‍💻 Desenvolvimento

Para contribuir com o projeto:

1. Faça um fork do repositório
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## 🤝 Contribuições

Contribuições são sempre bem-vindas! Sinta-se à vontade para reportar bugs ou sugerir novas funcionalidades.

## 📞 Suporte

Em caso de dúvidas ou problemas, abra uma issue no repositório ou entre em contato.

## 👨‍💻 Autor

- [Cláudio Henrique](https://github.com/claudiohpo)  

---

⭐️ Se este projeto te ajudou, deixe uma estrela no repositório!
