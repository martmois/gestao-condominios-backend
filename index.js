import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import multer from 'multer';
import xlsx from 'xlsx';
import vision from '@google-cloud/vision';
import { Storage } from '@google-cloud/storage';


dotenv.config();

const app = express();
const PORT = process.env.PORT || 8080;
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

// Configuração do Multer para upload de arquivos em memória
const upload = multer({ storage: multer.memoryStorage() });

/// --- LÓGICA DE CONEXÃO COM O BANCO DE DADOS ---
// Vamos padronizar o nome da nossa variável de conexão para 'pool'
const pool = await mysql.createPool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  socketPath: process.env.INSTANCE_CONNECTION_NAME ? `/cloudsql/${process.env.INSTANCE_CONNECTION_NAME}` : undefined,
  host: process.env.INSTANCE_CONNECTION_NAME ? undefined : process.env.DB_HOST,
});

// --- MUDANÇA: CONFIGURAÇÃO DO GOOGLE VISION CLIENT ---
// O cliente agora é inicializado com o caminho do segredo montado no Cloud Run.
const visionClient = new vision.ImageAnnotatorClient({
  keyFilename: '/etc/secrets/google-credentials.json' // Aponta para o caminho seguro
});


// Tarifa fixa em uma constante, pois ela é universal.
const TARIFA_FIXA_AGUA = 11.18;

// A tabela agora contém apenas as alíquotas variáveis.
const TABELA_VARIAVEL_CAESB = [
  { de: 1, ate: 7, aliquota: 4.13 },
  { de: 8, ate: 13, aliquota: 4.96 },
  { de: 14, ate: 20, aliquota: 9.82 },
  { de: 21, ate: 30, aliquota: 14.25 },
  { de: 31, ate: 45, aliquota: 21.37 },
  { de: 46, ate: Infinity, aliquota: 27.77 },
];

// MUDANÇA: Função de cálculo FINAL e CORRIGIDA
function calcularValorAgua(consumo, maxFaixaCondominioM3) {
    if (consumo <= 0) {
        return TARIFA_FIXA_AGUA;
    }

    let valorVariavel = 0;
    let consumoRestante = consumo;
    let consumoJaProcessado = 0;
    let aliquotaDaFaixaLimite = TABELA_VARIAVEL_CAESB[0].aliquota; // Default para a primeira faixa

    // 1. Encontrar a alíquota que corresponde ao maxFaixaCondominioM3
    for (const faixa of TABELA_VARIAVEL_CAESB) {
        if (maxFaixaCondominioM3 <= faixa.ate || faixa.ate === Infinity) {
            aliquotaDaFaixaLimite = faixa.aliquota;
            break;
        }
    }

    // 2. Processar o consumo da unidade
    for (const faixa of TABELA_VARIAVEL_CAESB) {
        if (consumoRestante <= 0) break; // Não há mais consumo para cobrar

        // Calcular o volume real da faixa (ex: 7m³ para 0-7, 6m³ para 8-13)
        const volumeDaFaixa = faixa.ate - (faixa.de - 1);

        // Se o consumo já processado atingiu ou ultrapassou o limite de volume da faixa limite do condomínio,
        // todo o restante do consumo da unidade será cobrado com a alíquota limite.
        if (consumoJaProcessado >= maxFaixaCondominioM3) {
            valorVariavel += consumoRestante * aliquotaDaFaixaLimite;
            consumoRestante = 0;
            break; // Termina o loop, pois todo o restante usa a alíquota limite
        }

        // Caso contrário, continua cobrando pelas faixas normais
        // Pega o mínimo entre o consumo restante e o volume da faixa atual
        let consumoNestaFaixa = Math.min(consumoRestante, volumeDaFaixa);
        
        // Se o consumoNestaFaixa (somado ao já processado) ultrapassaria a faixa limite do condomínio,
        // ajustamos para cobrar apenas até o limite com a alíquota da faixa atual, e o resto com a alíquota limite.
        if ((consumoJaProcessado + consumoNestaFaixa) > maxFaixaCondominioM3) {
            const consumoAteLimiteDaFaixaCondominio = maxFaixaCondominioM3 - consumoJaProcessado;
            if (consumoAteLimiteDaFaixaCondominio > 0) {
                valorVariavel += consumoAteLimiteDaFaixaCondominio * faixa.aliquota;
                consumoRestante -= consumoAteLimiteDaFaixaCondominio;
                consumoJaProcessado += consumoAteLimiteDaFaixaCondominio;
            }
            // O restante do consumo (que ultrapassou o maxFaixaCondominioM3) será cobrado
            // com a aliquotaDaFaixaLimite
            if (consumoRestante > 0) {
                valorVariavel += consumoRestante * aliquotaDaFaixaLimite;
                consumoRestante = 0; // Tudo cobrado
            }
            break; // Finaliza o loop
        } else {
            // Se ainda não atingiu o limite do condomínio, cobra normalmente nesta faixa
            valorVariavel += consumoNestaFaixa * faixa.aliquota;
            consumoRestante -= consumoNestaFaixa;
            consumoJaProcessado += consumoNestaFaixa;
        }
    }

    // Soma a parte variável com a tarifa fixa individual
    return valorVariavel + TARIFA_FIXA_AGUA;
}

// <-- MUDANÇA: NOSSO NOVO MIDDLEWARE "PORTEIRO"
// =================================================================
const verificarToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"

  if (!token) {
    return res.sendStatus(401); // Não autorizado, sem token
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, usuario) => {
    if (err) {
      return res.sendStatus(403); // Proibido, token inválido ou expirado
    }
    req.usuario = usuario; // Adiciona os dados do usuário (id, nome, tipo) ao objeto da requisição
    next(); // Passa para o próximo passo (a lógica da rota)
  });
};

// Inicialize o cliente do Cloud Storage (ele usará o mesmo google-credentials.json)
const storage = new Storage({ keyFilename: 'google-credentials.json' });
const bucketName = 'meu-app-hidrometros-fotos'; // <-- Substitua pelo nome do seu bucket
const bucket = storage.bucket(bucketName);

// NOVO: Função auxiliar para upload de imagem
async function uploadImageToGCS(buffer, filename) {
  const file = bucket.file(filename);
  // Torna o arquivo publicamente acessível. Ajuste se precisar de controle de acesso.
  const publicUrl = `https://storage.googleapis.com/${bucketName}/${filename}`;

  await file.save(buffer, {
    metadata: { contentType: 'image/jpeg' }, // Ou o tipo correto da imagem
    public: true, // Torna o arquivo publicamente legível
    resumable: false, // Desativa upload resumível (bom para arquivos pequenos)
  });

  return publicUrl;
}

// =================================================================
// ENDPOINTS DA API (ROTAS)
// =================================================================

// --- Rota Raiz de Teste ---
app.get('/', (req, res) => {
  res.send('Servidor backend do Sistema de Hidrômetros está rodando!');
});


// --- ROTAS PARA O GERENCIAMENTO DE CONDOMÍNIOS ---

// GET: Listar todos os condomínios
app.get('/api/condominios', verificarToken, async (req, res) => {
  try {
    const { tipo_usuario, id } = req.usuario; // Pega os dados do usuário do token decodificado

    let sql;
    let params;

    if (tipo_usuario === 'admin') {
      // Se for admin, busca todos os condomínios
      sql = 'SELECT * FROM condominios ORDER BY nome ASC';
      params = [];
    } else {
      // Se for leiturista, busca apenas os condomínios associados a ele
      sql = `
        SELECT c.* FROM condominios c
        JOIN usuario_condominio uc ON c.id = uc.condominio_id
        WHERE uc.usuario_id = ?
        ORDER BY c.nome ASC
      `;
      params = [id]; // Usa o ID do leiturista logado
    }

    const [results] = await pool.query(sql, params);
    res.json(results);

  } catch (error) {
    console.error('Erro ao buscar condomínios:', error);
    res.status(500).json({ error: 'Erro ao buscar dados do banco.' });
  }
});

// POST: Criar um novo condomínio
app.post('/api/condominios', async (req, res) => {
  try {
    const { nome, endereco, sindico, tipo_medicao } = req.body;
    if (!nome || !endereco || !sindico || !tipo_medicao) {
      return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
    }
    const sql = 'INSERT INTO condominios (nome, endereco, sindico, tipo_medicao) VALUES (?, ?, ?, ?)';
    const [results] = await pool.query(sql, [nome, endereco, sindico, tipo_medicao]);
    res.status(201).json({ id: results.insertId, nome, endereco, sindico, tipo_medicao });
  } catch (error) { /* ... */ }
});

// DELETE: Deletar um condomínio
app.delete('/api/condominios/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const sql = 'DELETE FROM condominios WHERE id = ?';
    const [results] = await pool.query(sql, [id]);
    if (results.affectedRows === 0) {
      return res.status(404).json({ error: 'Condomínio não encontrado.' });
    }
    res.status(200).json({ message: 'Condomínio deletado com sucesso.' });
  } catch (error) {
    console.error('Erro ao deletar condomínio:', error);
    res.status(500).json({ error: 'Erro ao deletar dados do banco.' });
  }
});

// PUT: Editar um condomínio
app.put('/api/condominios/:id', async (req, res) => {
  try {
    const { id } = req.params;
    // <-- MUDANÇA: Pega o tipo_medicao do corpo da requisição
    const { nome, endereco, sindico, tipo_medicao } = req.body;
    if (!nome || !endereco || !sindico || !tipo_medicao) {
      return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
    }
    const sql = 'UPDATE condominios SET nome = ?, endereco = ?, sindico = ?, tipo_medicao = ? WHERE id = ?';
    const [results] = await pool.query(sql, [nome, endereco, sindico, tipo_medicao, id]);
    if (results.affectedRows === 0) {
      return res.status(404).json({ error: 'Condomínio não encontrado.' });
    }
    res.status(200).json({ id: parseInt(id), nome, endereco, sindico, tipo_medicao });
  } catch (error) { /* ... */ }
});

// --- ROTAS PARA O GERENCIAMENTO DE USUÁRIOS ---

// POST: Cadastrar um novo usuário
app.post('/api/usuarios', async (req, res) => {
  try {
    const { nome, email, senha, tipo_usuario } = req.body;

    if (!nome || !email || !senha || !tipo_usuario) {
      return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
    }

    const saltRounds = 10;
    const senha_hash = await bcrypt.hash(senha, saltRounds);

    const sql = 'INSERT INTO usuarios (nome, email, senha_hash, tipo_usuario) VALUES (?, ?, ?, ?)';
    const [results] = await pool.query(sql, [nome, email, senha_hash, tipo_usuario]);

    res.status(201).json({ id: results.insertId, nome, email, tipo_usuario });

  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Este e-mail já está cadastrado.' });
    }
    console.error('Erro ao cadastrar usuário:', error);
    res.status(500).json({ error: 'Erro interno ao cadastrar usuário.' });
  }
});

// <-- MUDANÇA: NOVA ROTA PARA ATUALIZAR A SENHA DE UM USUÁRIO (PUT)
// =================================================================
app.put('/api/usuarios/:id/senha', async (req, res) => {
  try {
    const { id } = req.params;
    const { senha } = req.body;

    // Validação
    if (!senha) {
      return res.status(400).json({ error: 'O campo "senha" é obrigatório.' });
    }

    // Gerar o novo hash da senha
    const saltRounds = 10;
    const nova_senha_hash = await bcrypt.hash(senha, saltRounds);

    // Atualizar o hash da senha no banco de dados
    const sql = 'UPDATE usuarios SET senha_hash = ? WHERE id = ?';
    const [results] = await pool.query(sql, [nova_senha_hash, id]);

    if (results.affectedRows === 0) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    res.status(200).json({ message: 'Senha atualizada com sucesso.' });

  } catch (error) {
    console.error('Erro ao atualizar senha:', error);
    res.status(500).json({ error: 'Erro interno ao atualizar a senha.' });
  }
});
// =================================================================

// <-- MUDANÇA: NOVA ROTA PARA REALIZAR LOGIN (POST)
// =================================================================
app.post('/api/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) {
      return res.status(400).json({ error: 'Email e senha são obrigatórios.' });
    }

    // 1. Encontrar o usuário pelo email
    const sqlFindUser = 'SELECT * FROM usuarios WHERE email = ?';
    const [users] = await pool.query(sqlFindUser, [email]);

    if (users.length === 0) {
      // Usamos uma mensagem genérica para não informar se o email existe ou não (segurança)
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }
    const user = users[0];

    // 2. Comparar a senha enviada com o hash salvo no banco
    const isPasswordCorrect = await bcrypt.compare(senha, user.senha_hash);
    if (!isPasswordCorrect) {
      return res.status(401).json({ error: 'Credenciais inválidas.' });
    }

    // 3. Se a senha está correta, gerar o Token JWT
    const payload = { id: user.id, nome: user.nome, tipo_usuario: user.tipo_usuario };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

    // 4. Enviar o token para o frontend
    res.status(200).json({
      message: 'Login bem-sucedido!',
      token: token,
      user: payload // Enviamos também os dados do usuário para o frontend usar
    });

  } catch (error) {
    console.error('Erro no login:', error);
    res.status(500).json({ error: 'Erro interno no servidor.' });
  }
});

// Usamos upload.single('arquivo') como um "middleware" que processa o arquivo antes da nossa lógica.
// 'arquivo' é o nome do campo que o frontend deverá usar para enviar o arquivo.
app.post('/api/condominios/:id/importar', upload.single('arquivo'), async (req, res) => {
  const condominioId = req.params.id;

  if (!req.file) {
    return res.status(400).json({ error: 'Nenhum arquivo enviado.' });
  }

  // Usamos uma transação para garantir a integridade dos dados
  let connection;
  try {
    connection = await pool.getConnection();
    await connection.beginTransaction();

    // Lê o buffer do arquivo enviado com a biblioteca xlsx
    const workbook = xlsx.read(req.file.buffer, { type: 'buffer' });
    const sheetName = workbook.SheetNames[0];
    const sheet = workbook.Sheets[sheetName];
    const data = xlsx.utils.sheet_to_json(sheet);

    let unidadesAdicionadas = 0;
    
    // Processa cada linha da planilha
    for (const row of data) {
      const { BLOCO, ANDAR, UNIDADE } = row;

      if (!BLOCO || !ANDAR || !UNIDADE) {
        // Se alguma linha não tiver os dados obrigatórios, desfazemos tudo
        throw new Error('Todas as linhas devem conter BLOCO, ANDAR e UNIDADE.');
      }

      // 1. Verifica se o bloco já existe, se não, cria.
      let blocoId;
      const [blocosExistentes] = await connection.query('SELECT id FROM blocos WHERE nome_bloco = ? AND condominio_id = ?', [BLOCO, condominioId]);
      
      if (blocosExistentes.length > 0) {
        blocoId = blocosExistentes[0].id;
      } else {
        const [resultBloco] = await connection.query('INSERT INTO blocos (nome_bloco, condominio_id) VALUES (?, ?)', [BLOCO, condominioId]);
        blocoId = resultBloco.insertId;
      }

      // 2. Insere a unidade, associando ao bloco
      await connection.query('INSERT INTO unidades (identificador_unidade, andar, bloco_id) VALUES (?, ?, ?)', [UNIDADE, ANDAR, blocoId]);
      unidadesAdicionadas++;
    }

    // Se tudo deu certo, confirma as alterações no banco de dados
    await connection.commit();
    res.status(200).json({ message: `${unidadesAdicionadas} unidades importadas com sucesso!` });

  } catch (error) {
    // Se qualquer erro ocorrer, desfaz todas as operações
    if (connection) await connection.rollback();
    console.error('Erro na importação:', error);
    res.status(500).json({ error: 'Falha na importação. Nenhuma unidade foi adicionada.', details: error.message });
  } finally {
    // Libera a conexão com o banco
    if (connection) connection.release();
  }
});


// <-- ROTA PARA BUSCAR DETALHES DE UM CONDOMÍNIO
app.get('/api/condominios/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const sql = `
      SELECT
        c.id as condominio_id, c.nome as condominio_nome, c.endereco, c.sindico, c.tipo_medicao,
        b.id as bloco_id, b.nome_bloco,
        u.id as unidade_id, u.identificador_unidade, u.andar
      FROM condominios c
      LEFT JOIN blocos b ON c.id = b.condominio_id
      LEFT JOIN unidades u ON b.id = u.bloco_id
      WHERE c.id = ?
      ORDER BY b.nome_bloco, u.andar, u.identificador_unidade;
    `;
    const [rows] = await pool.query(sql, [id]);
    if (rows.length === 0) return res.status(404).json({ error: 'Condomínio não encontrado.' });
    
    // Processa os dados para um formato aninhado
    const condominioDetails = {
      id: rows[0].condominio_id,
      nome: rows[0].condominio_nome,
      endereco: rows[0].endereco,
      sindico: rows[0].sindico,
      tipo_medicao: rows[0].tipo_medicao, // <-- Adicionado para passar para o frontend
      blocos: {},
    };
    for (const row of rows) {
      if (row.bloco_id) {
        if (!condominioDetails.blocos[row.bloco_id]) {
          condominioDetails.blocos[row.bloco_id] = { id: row.bloco_id, nome: row.nome_bloco, unidades: [], };
        }
        if (row.unidade_id) {
          condominioDetails.blocos[row.bloco_id].unidades.push({
            id: row.unidade_id,
            identificador_unidade: row.identificador_unidade, // <-- Nome corrigido aqui
            andar: row.andar,
          });
        }
      }
    }
    condominioDetails.blocos = Object.values(condominioDetails.blocos);
    res.json(condominioDetails);
  } catch (error) {
    console.error('Erro ao buscar detalhes do condomínio:', error);
    res.status(500).json({ error: 'Erro ao buscar dados.' });
  }
});

// ROTA PARA BUSCAR DETALHES DE UMA UNIDADE E SUAS LEITURAS
// =================================================================
app.get('/api/unidades/:id', async (req, res) => {
  const { id } = req.params;
  try {
    // Query 1: Busca os detalhes da unidade e sua hierarquia (bloco, condomínio)
    const sqlUnidade = `
      SELECT
        u.id as unidade_id, u.identificador_unidade, u.andar,
        b.id as bloco_id, b.nome_bloco,
        c.id as condominio_id, c.nome as condominio_nome
      FROM unidades u
      JOIN blocos b ON u.bloco_id = b.id
      JOIN condominios c ON b.condominio_id = c.id
      WHERE u.id = ?;
    `;
    const [unidadeResult] = await pool.query(sqlUnidade, [id]);

    if (unidadeResult.length === 0) {
      return res.status(404).json({ error: 'Unidade não encontrada.' });
    }

    // Query 2: Busca o histórico de leituras para essa unidade
    const sqlLeituras = `
      SELECT
        l.id as leitura_id, l.leitura_agua_fria, l.leitura_agua_quente, l.data_leitura,
        usr.nome as leiturista_nome
      FROM leituras l
      JOIN usuarios usr ON l.leiturista_id = usr.id
      WHERE l.unidade_id = ?
      ORDER BY l.data_leitura DESC;
    `;
    const [leiturasResult] = await pool.query(sqlLeituras, [id]);

    // Combina os resultados em um único objeto de resposta
    const responseData = {
      ...unidadeResult[0],
      leituras: leiturasResult,
    };

    res.json(responseData);

  } catch (error) {
    console.error('Erro ao buscar detalhes da unidade:', error);
    res.status(500).json({ error: 'Erro ao buscar dados.' });
  }
});

// <-- ROTA PARA BUSCAR AS UNIDADES DE UM BLOCO ESPECÍFICO
app.get('/api/blocos/:id/unidades', verificarToken, async (req, res) => {
  try {
    const { id } = req.params; // ID do Bloco
    const sql = 'SELECT id, identificador_unidade, andar FROM unidades WHERE bloco_id = ?';
    const [unidades] = await pool.query(sql, [id]);
    res.json(unidades);
  } catch (error) {
    console.error('Erro ao buscar unidades do bloco:', error);
    res.status(500).json({ error: 'Erro ao buscar dados.' });
  }
});

// <-- ROTA PARA BUSCAR UMA FATURA ESPECÍFICA POR PERÍODO
app.get('/api/faturas', async (req, res) => {
  try {
    const { condominioId, ano, mes } = req.query;
    if (!condominioId || !ano || !mes) {
      return res.status(400).json({ error: 'Condomínio, ano e mês são obrigatórios.' });
    }

    const sql = 'SELECT * FROM faturas_gerais WHERE condominio_id = ? AND ano = ? AND mes = ?';
    const [results] = await pool.query(sql, [condominioId, ano, mes]);

    if (results.length > 0) {
      res.json(results[0]); // Retorna a fatura encontrada
    } else {
      res.json(null); // Retorna nulo se nenhuma fatura for encontrada
    }
  } catch (error) {
    console.error('Erro ao buscar fatura:', error);
    res.status(500).json({ error: 'Erro ao buscar dados da fatura.' });
  }
});

// Rota GET: Gera o relatório de consumo e rateio para um condomínio e período
app.get('/api/relatorios/consumo', async (req, res) => {
  try {
    // 1. Validação dos parâmetros de entrada
    const { condominioId, ano, mes } = req.query;
    if (!condominioId || !ano || !mes) {
      return res.status(400).json({ error: 'Condomínio, ano e mês são obrigatórios.' });
    }

    // 2. Busca a configuração do condomínio (tipo de medição)
    const [condominioConfig] = await pool.query('SELECT tipo_medicao FROM condominios WHERE id = ?', [condominioId]);
    if (condominioConfig.length === 0) {
      return res.status(404).json({ error: 'Condomínio não encontrado.' });
    }
    const { tipo_medicao } = condominioConfig[0];

    // NOVO: 3. Obter o consumo total do condomínio da fatura geral 
    const [faturaCondominioResult] = await pool.query(
      'SELECT consumo_total_m3 FROM faturas_gerais WHERE condominio_id = ? AND ano = ? AND mes = ?',
      [condominioId, ano, mes]
    );

    if (faturaCondominioResult.length === 0 || !faturaCondominioResult[0].consumo_total_m3) {
      // Se não houver fatura geral lançada, não é possível fazer o rateio
      return res.status(400).json({ error: 'Fatura geral do condomínio não encontrada para este período ou consumo total não registrado.' });
    }
    const consumoTotalCondominio = faturaCondominioResult[0].consumo_total_m3; // 

    // NOVO: 4. Obter o número total de unidades do condomínio
    const [unidadesNoCondominioResult] = await pool.query(`
      SELECT COUNT(u.id) AS total_unidades
      FROM unidades u
      JOIN blocos b ON u.bloco_id = b.id
      WHERE b.condominio_id = ?
    `, [condominioId]);

    const numUnidadesConsumidoras = unidadesNoCondominioResult[0].total_unidades; //

    if (numUnidadesConsumidoras === 0) {
      return res.status(400).json({ error: 'Nenhuma unidade registrada para este condomínio para o rateio.' });
    }

    // NOVO: 5. Calcular Consumo Médio e Faixa Máxima do Condomínio 
    const consumoMedioPorUnidadeCondominio = consumoTotalCondominio / numUnidadesConsumidoras;

    let faixaMaximaCondominioM3 = 0;
    // Se o consumo médio for <= 0, a faixa máxima ainda será a primeira faixa (0-7m³)
    if (consumoMedioPorUnidadeCondominio <= 0) {
        faixaMaximaCondominioM3 = TABELA_VARIAVEL_CAESB[0].ate; // Assume o limite da primeira faixa (7m³)
    } else {
        // Encontra a faixa onde o consumo médio se encaixa
        for (const faixa of TABELA_VARIAVEL_CAESB) { // 
            if (consumoMedioPorUnidadeCondominio <= faixa.ate || faixa.ate === Infinity) {
                faixaMaximaCondominioM3 = faixa.ate; // Define o limite superior da faixa como o máximo a ser cobrado
                break;
            }
        }
    }
    // Caso raro onde o consumo médio é tão alto que excede todas as faixas (faixa.ate === Infinity)
    if (faixaMaximaCondominioM3 === 0 && consumoMedioPorUnidadeCondominio > 0) {
        faixaMaximaCondominioM3 = TABELA_VARIAVEL_CAESB[TABELA_VARIAVEL_CAESB.length - 1].ate;
    }


    // 6. Prepara as datas para a consulta SQL (já existente)
    const periodoAtual = `${ano}-${mes.toString().padStart(2, '0')}`;
    const dataAtual = new Date(ano, mes - 1, 1);
    const dataAnterior = new Date(new Date(dataAtual).setMonth(dataAtual.getMonth() - 1));
    const periodoAnterior = `${dataAnterior.getFullYear()}-${(dataAnterior.getMonth() + 1).toString().padStart(2, '0')}`;

    // 7. Executa a consulta SQL compatível para buscar leituras atuais e anteriores (já existente)
    const sql = `
      SELECT
        b.nome_bloco,
        u.identificador_unidade,
        COALESCE(leitura_anterior.leitura_agua_fria, 0) as leitura_anterior_fria,
        leitura_atual.leitura_agua_fria as leitura_atual_fria,
        (leitura_atual.leitura_agua_fria - COALESCE(leitura_anterior.leitura_agua_fria, 0)) as consumo_fria,
        COALESCE(leitura_anterior.leitura_agua_quente, 0) as leitura_anterior_quente,
        leitura_atual.leitura_agua_quente as leitura_atual_quente,
        (leitura_atual.leitura_agua_quente - COALESCE(leitura_anterior.leitura_agua_quente, 0)) as consumo_quente
      FROM 
        (SELECT * FROM leituras WHERE DATE_FORMAT(data_leitura, '%Y-%m') = ?) AS leitura_atual
      LEFT JOIN 
        (SELECT * FROM leituras WHERE DATE_FORMAT(data_leitura, '%Y-%m') = ?) AS leitura_anterior 
        ON leitura_atual.unidade_id = leitura_anterior.unidade_id
      JOIN unidades u ON leitura_atual.unidade_id = u.id
      JOIN blocos b ON u.bloco_id = b.id
      WHERE b.condominio_id = ?
    `;
    const [results] = await pool.query(sql, [periodoAtual, periodoAnterior, condominioId]);

    // 8. Mapeia os resultados e aplica a lógica de cálculo de tarifa CAESB corrigida 
    const reportComValores = results.map(row => {
      const consumoAguaQuente = tipo_medicao === 'FRIA_E_QUENTE' ? row.consumo_quente : 0;
      
      // Passa a faixaMaximaCondominioM3 para a função de cálculo
      const valorAguaFria = calcularValorAgua(row.consumo_fria, faixaMaximaCondominioM3); // 
      const valorAguaQuente = tipo_medicao === 'FRIA_E_QUENTE' 
        ? calcularValorAgua(consumoAguaQuente, faixaMaximaCondominioM3) // 
        : 0;
      
      const valorTotalAgua = valorAguaFria + valorAguaQuente;
      const valorEsgoto = valorTotalAgua; // Esgoto é 100%
      
      // NOVO: Cálculo da Tarifa Fixa para a unidade (para ser somado no total, se necessário).
      // A tarifa fixa de água individual já está inclusa no calcularValorAgua.
      // O texto da fatura diz "Tarifa Fixa de Água Residencial Padrao 268.32", que é 11.18 * 24.
      // Aqui estamos calculando para a unidade individual (11.18), já dentro do calcularValorAgua.
      // Então, o valor total a pagar já estará correto considerando a fixa individual.
      
      const valorTotalPagar = valorTotalAgua + valorEsgoto;

      return {
        ...row,
        consumo_quente: consumoAguaQuente,
        valor_total_pagar: valorTotalPagar.toFixed(2),
        // Adicione para fins de depuração/verificação:
        consumo_medio_condominio: consumoMedioPorUnidadeCondominio.toFixed(2),
        faixa_maxima_condominio_m3: faixaMaximaCondominioM3
      };
    });

    // 9. Envia a resposta completa para o frontend
    res.json({
      tipo_medicao: tipo_medicao,
      consumo_total_condominio_fatura: consumoTotalCondominio,
      num_unidades_condominio: numUnidadesConsumidoras,
      consumo_medio_condominio: consumoMedioPorUnidadeCondominio.toFixed(2),
      faixa_maxima_condominio_m3: faixaMaximaCondominioM3,
      dados: reportComValores
    });
  } catch (error) {
    console.error('Erro ao gerar relatório de consumo:', error);
    res.status(500).json({ error: 'Erro ao gerar relatório.' });
  }
});

// Rota para Cadastrar/Atualizar uma Fatura Geral
app.post('/api/faturas', async (req, res) => {
  try {
    const {
      condominio_id,
      mes,
      ano,
      consumo_total_m3,
      // <-- MUDANÇA: Recebemos apenas os valores que o usuário digita
      valor_variavel_agua,
      valor_fixa_agua
    } = req.body;

    // Validação dos dados recebidos
    if (!condominio_id || !mes || !ano || !consumo_total_m3 || valor_variavel_agua === undefined || valor_fixa_agua === undefined) {
      return res.status(400).json({ error: 'Todos os campos de entrada são obrigatórios.' });
    }

    // <-- MUDANÇA: O backend agora calcula os totais
    const valor_agua_total = parseFloat(valor_variavel_agua) + parseFloat(valor_fixa_agua);
    const valor_esgoto = valor_agua_total; // Esgoto é 100% do total da água
    const valor_total_fatura = valor_agua_total + valor_esgoto;

    const sql = `
      INSERT INTO faturas_gerais 
        (condominio_id, mes, ano, consumo_total_m3, valor_variavel_agua, valor_fixa_agua, valor_esgoto, valor_total_fatura)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        consumo_total_m3 = VALUES(consumo_total_m3),
        valor_variavel_agua = VALUES(valor_variavel_agua),
        valor_fixa_agua = VALUES(valor_fixa_agua),
        valor_esgoto = VALUES(valor_esgoto),
        valor_total_fatura = VALUES(valor_total_fatura);
    `;

    await pool.query(sql, [
      condominio_id, mes, ano, consumo_total_m3,
      valor_variavel_agua, valor_fixa_agua,
      valor_esgoto, valor_total_fatura
    ]);

    res.status(201).json({ message: 'Fatura lançada com sucesso!' });
  } catch (error) {
    console.error('Erro ao lançar fatura:', error);
    res.status(500).json({ error: 'Erro interno ao lançar a fatura.' });
  }
});

// <-- ROTA PARA SALVAR UMA LEITURA (POST)
app.post('/api/leituras', verificarToken, async (req, res) => {
  try {
    const { 
      unidade_id, 
      leitura_agua_fria, 
      leitura_agua_quente,
      foto_fria_url, // <-- Adicionado
      foto_quente_url // <-- Adicionado
    } = req.body;
    const leiturista_id = req.usuario.id; // Pegamos o ID do leiturista do token JWT

    if (!unidade_id || leitura_agua_fria === undefined || leitura_agua_quente === undefined) {
      return res.status(400).json({ error: 'Dados da leitura incompletos.' });
    }

    const sql = `
      INSERT INTO leituras (unidade_id, leitura_agua_fria, leitura_agua_quente, leiturista_id, data_leitura, foto_fria_url, foto_quente_url)
      VALUES (?, ?, ?, ?, NOW(), ?, ?)
    `;

    await pool.query(sql, [
      unidade_id, 
      leitura_agua_fria, 
      leitura_agua_quente, 
      leiturista_id,
      foto_fria_url, // <-- Passa o valor
      foto_quente_url // <-- Passa o valor
    ]);

    res.status(201).json({ message: 'Leitura salva com sucesso!' });
  } catch (error) {
    console.error('Erro ao salvar leitura:', error);
    res.status(500).json({ error: 'Erro interno ao salvar a leitura.' });
  }
});




// ROTA POST para OCR (agora com upload)
app.post('/api/ocr/analisar-imagem', verificarToken, upload.single('imagem'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Nenhuma imagem enviada.' });
  }

  try {
    const content = req.file.buffer;

    // Acessar os novos dados enviados pelo frontend via req.body
    const { 
        unidadeId, 
        identificadorUnidade, 
        tipoLeitura,
        blocoId, // embora não usado no nome diretamente, pode ser útil
        condominioNome
    } = req.body;

    // Formatar a data para o nome do arquivo (YYYYMMDD_HHMMSS)
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    const hours = String(now.getHours()).padStart(2, '0');
    const minutes = String(now.getMinutes()).padStart(2, '0');
    const seconds = String(now.getSeconds()).padStart(2, '0');
    const dateFormatted = `${year}${month}${day}_${hours}${minutes}${seconds}`;

    // Sanitizar o nome do condomínio para uso em nome de arquivo
    const sanitizedCondominioNome = condominioNome ? condominioNome.replace(/[^a-zA-Z0-9]/g, '_').substring(0, 30) : 'cond'; // Limita a 30 caracteres
    const sanitizedBlocoId = blocoId ? `bl${blocoId}` : 'bl_na'; // Exemplo de abreviação

    // Construir o nome do arquivo
    // Exemplo: MAISON_UNID101_ANDAR1_FRIO_20250719_103045.jpg
    const filename = `${sanitizedCondominioNome}_BL${sanitizedBlocoId}_UNID${identificadorUnidade}_${tipoLeitura.toUpperCase()}_${dateFormatted}.jpg`;
    
    const imageUrl = await uploadImageToGCS(content, filename);

    const [result] = await visionClient.textDetection({ image: { content } });
    const detections = result.textAnnotations;

    if (!detections || detections.length === 0) {
      return res.status(404).json({ error: 'Nenhum texto encontrado na imagem.', imageUrl: imageUrl });
    }

    const textoCompleto = detections[0].description;
    const numerosEncontrados = textoCompleto.match(/\d+/g)?.join('') || '';
    const leitura = numerosEncontrados.substring(0, 5);

    if (!leitura) {
        return res.status(404).json({ error: 'Nenhum número de leitura válido foi identificado.', imageUrl: imageUrl });
    }

    res.json({ leitura: leitura, imageUrl: imageUrl });
  } catch (error) {
    console.error('Erro na API do Google Vision ou upload:', error);
    res.status(500).json({ error: 'Falha ao analisar a imagem ou fazer upload.' });
  }
});

// --- Inicialização do Servidor ---
app.listen(PORT, () => {
  console.log(`Servidor backend rodando na porta ${PORT}`);
});