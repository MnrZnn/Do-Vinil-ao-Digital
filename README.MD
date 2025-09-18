Guia de Implantação: Do Vinil ao Digital
Este guia detalha o processo para colocar sua aplicação online, com o front-end no GitHub Pages, o back-end no Render e o banco de dados MySQL no Railway.

Estrutura do Projeto
Para a implantação, seu projeto precisa estar em um repositório no GitHub com os seguintes arquivos:

index.html (front-end)

api.py (back-end)

requirements.txt (dependências do back-end)

README.md (este guia)

Parte 1: Configurar o Banco de Dados MySQL no Railway
O Railway nos fornecerá um banco de dados MySQL na nuvem gratuitamente.

Crie uma Conta: Acesse railway.app e crie uma conta (você pode usar sua conta do GitHub para facilitar).

Crie um Novo Projeto: No seu painel (dashboard), clique em New Project e depois escolha Provision MySQL.

Obtenha as Credenciais: Após alguns segundos, o banco será criado. Vá para a aba Connect do seu banco de dados MySQL no Railway. Você verá todas as informações de que precisa:

MYSQLHOST (Endereço do servidor)

MYSQLUSER (Usuário)

MYSQLPASSWORD (Senha)

MYSQLPORT (Porta)

MYSQLDATABASE (Nome do banco)

Construa a URL de Conexão: Junte essas informações no seguinte formato. Guarde esta URL, você a usará na Parte 2.

mysql+pymysql://USUARIO:SENHA@HOST:PORTA/BANCO_DE_DADOS

Substitua USUARIO, SENHA, HOST, PORTA e BANCO_DE_DADOS pelos valores que você pegou do Railway.

Parte 2: Implantar o Back-end (API) no Render
O Render irá hospedar e executar nosso código Python (api.py).

Crie uma Conta: Acesse render.com e crie uma conta, conectando-a ao seu GitHub.

Crie um Novo Serviço Web:

No painel do Render, clique em New + e depois em Web Service.

Conecte o repositório do GitHub que contém seus arquivos de projeto.

Configure o Serviço:

Name: Dê um nome único para sua API (ex: vinil-digital-api).

Root Directory: Deixe em branco se seus arquivos estiverem na raiz do repositório.

Runtime: Python 3.

Build Command: pip install -r requirements.txt.

Start Command: gunicorn api:app.

Adicione as Variáveis de Ambiente (MUITO IMPORTANTE):

Clique em Advanced, depois em Add Environment Variable.

Adicione as seguintes variáveis:

DATABASE_URL: Cole a URL de conexão completa que você montou na Parte 1.

JWT_SECRET_KEY: Crie uma senha longa e secreta aqui. Pode ser qualquer texto aleatório e seguro. (Ex: d8f3b6a2c1e9f4a7b0d8e1c3f5a9b7d2).

PYTHON_VERSION: Coloque 3.10.6 (ou uma versão Python 3 recente).

FRONTEND_URL: Por enquanto, deixe com o valor *. Vamos atualizar isso na Parte 3.

Faça a Implantação (Deploy): Clique em Create Web Service. O Render vai instalar as dependências e iniciar sua API. O primeiro deploy pode demorar alguns minutos.

Copie a URL da API: Após o deploy ser concluído com sucesso, o Render fornecerá uma URL pública para sua API no topo da página (ex: https://vinil-digital-api.onrender.com). Copie e guarde esta URL.

Parte 3: Implantar o Front-end no GitHub Pages e Conectar Tudo
Agora, vamos colocar o site no ar e fazer a conexão final.

Atualize a URL da API no index.html:

Abra o arquivo index.html no seu editor de código (ou diretamente no GitHub).

Encontre a linha: API_BASE_URL: '',

Cole a URL da sua API do Render que você copiou no passo anterior. Deve ficar assim:

API_BASE_URL: '[https://vinil-digital-api.onrender.com](https://vinil-digital-api.onrender.com)', // Exemplo

Salve e envie (commit/push) esta alteração para o seu repositório no GitHub.

Ative o GitHub Pages:

No seu repositório no GitHub, vá para Settings > Pages.

Na seção Branch, selecione a branch main (ou master) e a pasta /root. Clique em Save.

Aguarde alguns minutos. O GitHub vai publicar seu site e te dar a URL pública (ex: https://seu-usuario.github.io/nome-do-repositorio/).

Atualize a Variável FRONTEND_URL no Render (Passo Final de Segurança):

Volte ao seu serviço web no Render.

Vá para a aba Environment.

Edite a variável de ambiente FRONTEND_URL.

Cole a URL do seu site no GitHub Pages que você acabou de obter.

Clique em Save Changes. O Render irá reiniciar sua API com a nova configuração de segurança.

Pronto! Agora você tem uma aplicação web totalmente funcional e online. Os usuários podem acessar seu site no GitHub Pages, se cadastrar, e os dados serão enviados para sua API no Render, que por sua vez os salvará no seu banco de dados MySQL no Railway.

mysql+pymysql://root:mSSAEaamMLibNKtugQjUFvWPIHdsPVgy@mysql.railway.internal:3306/railway




