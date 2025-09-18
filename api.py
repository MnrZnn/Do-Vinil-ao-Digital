import os
from datetime import timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURAÇÃO ---
app = Flask(__name__)

FRONTEND_URL = os.environ.get('FRONTEND_URL', '*')
CORS(app, resources={r"/*": {"origins": FRONTEND_URL}})

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24)

# Ainda usamos SQLAlchemy para gerenciamento de conexão, mas não para seus recursos de ORM.
db = SQLAlchemy(app)
jwt = JWTManager(app)

# --- INICIALIZAÇÃO DO ESQUEMA DO BANCO DE DADOS ---
def init_db():
    """Inicializa o banco de dados com comandos SQL CREATE TABLE."""
    
    # Comando SQL para criar a tabela 'user' se ela não existir.
    # "user" é uma palavra-chave reservada, então é mais seguro usar aspas.
    create_user_table = text("""
        CREATE TABLE IF NOT EXISTS "user" (
            id SERIAL PRIMARY KEY,
            name VARCHAR(150) NOT NULL,
            email VARCHAR(150) UNIQUE NOT NULL,
            password_hash VARCHAR(256) NOT NULL
        );
    """)

    # Comando SQL para criar a tabela 'record' se ela não existir.
    create_record_table = text("""
        CREATE TABLE IF NOT EXISTS record (
            id SERIAL PRIMARY KEY,
            album VARCHAR(200) NOT NULL,
            artist VARCHAR(200) NOT NULL,
            year INTEGER,
            cover_url VARCHAR(500),
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES "user" (id) ON DELETE CASCADE
        );
    """)
    
    with app.app_context():
        # Executa os comandos de criação de tabela.
        db.session.execute(create_user_table)
        db.session.execute(create_record_table)
        db.session.commit()

# --- ROTAS DA API COM SQL PURO ---

@app.route('/warmup', methods=['GET'])
def warmup():
    return jsonify({'status': 'server is awake'}), 200

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({'message': 'Dados incompletos fornecidos.'}), 400

    # SQL para verificar se o email existe. Usando parâmetros para prevenir SQL Injection.
    sql_check_email = text('SELECT id FROM "user" WHERE email = :email')
    user = db.session.execute(sql_check_email, {'email': data['email']}).fetchone()

    if user:
        return jsonify({'message': 'Este email já está em uso.'}), 409
        
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    # SQL para inserir um novo usuário.
    sql_insert_user = text(
        'INSERT INTO "user" (name, email, password_hash) VALUES (:name, :email, :password)'
    )
    
    try:
        db.session.execute(sql_insert_user, {
            'name': data['name'],
            'email': data['email'],
            'password': hashed_password
        })
        db.session.commit()
        return jsonify({'message': 'Usuário criado com sucesso!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Erro interno do servidor: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Email e senha são obrigatórios.'}), 400
        
    # SQL para buscar id e hash da senha para validação.
    sql_get_user = text('SELECT id, password_hash FROM "user" WHERE email = :email')
    result = db.session.execute(sql_get_user, {'email': data['email']}).fetchone()
    
    if not result or not check_password_hash(result.password_hash, data['password']):
        return jsonify({'message': 'Credenciais inválidas.'}), 401
    
    user_id = result.id
    access_token = create_access_token(identity=user_id)
    return jsonify(access_token=access_token)

@app.route('/collection', methods=['GET'])
@jwt_required()
def get_collection():
    current_user_id = get_jwt_identity()
    
    # SQL para obter todos os discos do usuário atual.
    sql_get_records = text(
        'SELECT id, album, artist, year, cover_url FROM record '
        'WHERE user_id = :user_id ORDER BY created_at DESC'
    )
    results = db.session.execute(sql_get_records, {'user_id': current_user_id}).fetchall()
    
    # Converte a lista de resultados em uma lista de dicionários para o JSON.
    output = [row._asdict() for row in results]
        
    return jsonify(output)

@app.route('/records', methods=['POST'])
@jwt_required()
def add_record():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or not data.get('album') or not data.get('artist'):
         return jsonify({'message': 'Álbum e Artista são obrigatórios.'}), 400
         
    # SQL para inserir um novo disco. RETURNING id funciona com PostgreSQL.
    sql_insert_record = text(
        'INSERT INTO record (album, artist, year, cover_url, user_id) '
        'VALUES (:album, :artist, :year, :cover_url, :user_id) RETURNING id'
    )
    
    try:
        result = db.session.execute(sql_insert_record, {
            'album': data['album'],
            'artist': data['artist'],
            'year': data.get('year'),
            'cover_url': data.get('cover_url'),
            'user_id': current_user_id
        }).fetchone()
        db.session.commit()
        new_record_id = result.id
        return jsonify({'message': 'Disco adicionado com sucesso!', 'id': new_record_id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Erro interno do servidor: {str(e)}'}), 500

if __name__ == '__main__':
    # Inicializa o banco de dados antes de rodar a aplicação.
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

