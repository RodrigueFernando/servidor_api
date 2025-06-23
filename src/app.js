import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from "bcryptjs";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

// 🔑 Segredo do JWT

const JWT_SECRET = 'ifsp2025';

const users = [];
s
//Mock de alunos
const alunos = [
    { id: 1, nome: "Asdrubal", ra: "11111", nota1: 8.5, nota2: 9.5 },
    { id: 2, nome: "Lupita", ra: "22222", nota1: 7.5, nota2: 7 },
    { id: 3, nome: "Zoroastro", ra: "33333", nota1: 3, nota2: 4 }
];

//Middleware de autenticação
function autenticarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Acesso negado. Token não fornecido.' });
    }

    jwt.verify(token, JWT_SECRET, (err, userPayload) => {
        if (err) return res.status(403).json({ message: 'Token inválido.' });
        req.user = userPayload; // Armazena o payload do token em req.user
        next();
    });
}

// ===================== ROTAS =====================

//Registro de usuário
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (users.find(u => u.username === username)) {
        return res.status(400).json({ message: 'Usuário já existe!' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ username, password: hashedPassword });
    console.log("Usuário registrado:", users);
    res.status(201).json({ message: 'Usuário registrado com sucesso!' });
});

// Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Login incorreto!' });
    }

    const token = jwt.sign(
        { username: user.username },
        JWT_SECRET,
        { expiresIn: '1h', algorithm: 'HS256' }
    );

    res.json({ message: 'Login realizado com sucesso!', token });
    console.log('Login efetuado pelo usuário ' + user.username);
});

//Listar todos os alunos
app.get('/alunos', autenticarToken, (req, res) => {
    res.json(alunos);
});

// -------------------------------------------------------------
// IMPORTANTE: Rotas mais específicas para alunos devem vir antes das genéricas!
// -------------------------------------------------------------

//Listar alunos e suas médias
app.get('/alunos/medias', autenticarToken, (req, res) => {
    const resultado = alunos.map(a => ({
        nome: a.nome,
        media: ((a.nota1 + a.nota2) / 2).toFixed(2)
    }));
    res.json(resultado);
});

//Listar alunos aprovados
app.get('/alunos/aprovados', autenticarToken, (req, res) => {
    const resultado = alunos.filter(a => ((a.nota1 + a.nota2) / 2) >= 6).map(a => ({
        nome: a.nome,
        media: ((a.nota1 + a.nota2) / 2).toFixed(2)
    }));
    res.json(resultado);
});

//Listar alunos reprovados
app.get('/alunos/reprovados', autenticarToken, (req, res) => {
    const resultado = alunos.filter(a => ((a.nota1 + a.nota2) / 2) < 6).map(a => ({
        nome: a.nome,
        media: ((a.nota1 + a.nota2) / 2).toFixed(2)
    }));
    res.json(resultado);
});

// Buscar aluno por ID
app.get('/alunos/:id', autenticarToken, (req, res) => {
    const aluno = alunos.find(a => a.id === parseInt(req.params.id));

    if (!aluno) {
        return res.status(404).json({ message: 'Aluno não encontrado!' });
    }

    res.json(aluno);
});

//Cadastrar novo aluno
app.post('/alunos', autenticarToken, (req, res) => {
    const { id, nome, ra, nota1, nota2 } = req.body;
    // Validação básica para evitar adicionar alunos sem ID ou RA duplicado (se necessário)
    if (!id || !nome || !ra) {
        return res.status(400).json({ message: 'Dados mínimos (id, nome, ra) são obrigatórios.' });
    }
    if (alunos.find(a => a.id === id || a.ra === ra)) { // Checa ID e RA duplicados
        return res.status(400).json({ message: 'ID ou RA já cadastrado!' });
    }
    alunos.push({ id, nome, ra, nota1, nota2 });
    res.status(201).json({ message: 'Aluno criado com sucesso!' });
});

// Atualizar aluno.
app.put('/alunos/:id', autenticarToken, (req, res) => {
    const aluno = alunos.find(a => a.id === parseInt(req.params.id));

    if (!aluno) {
        return res.status(404).json({ message: 'Aluno não encontrado!' });
    }

    const { nome, ra, nota1, nota2 } = req.body;

    aluno.nome = nome ?? aluno.nome;
    aluno.ra = ra ?? aluno.ra;
    aluno.nota1 = nota1 ?? aluno.nota1;
    aluno.nota2 = nota2 ?? aluno.nota2;

    res.json({ message: 'Aluno atualizado com sucesso!', aluno: aluno }); // Retornar o aluno atualizado é útil
});

//Deletar aluno
app.delete('/alunos/:id', autenticarToken, (req, res) => {
    const index = alunos.findIndex(a => a.id === parseInt(req.params.id));

    if (index === -1) {
        return res.status(404).json({ message: 'Aluno não encontrado!' });
    }

    alunos.splice(index, 1);

    res.json({ message: 'Aluno removido com sucesso!' });
});

//Inicialização do servidor
const PORT = 3001; // Definindo a porta em uma constante para clareza
app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`); // Mensagem corrigida
});

export default app;