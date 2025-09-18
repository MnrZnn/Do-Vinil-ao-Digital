import os
from datetime import timedelta, datetime
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity
from dotenv import load_dotenv

load_dotenv() # Carrega variáveis de ambiente de um arquivo .env

# --- CONFIGURAÇÃO ---
app = Flask(__name__)

# Configuração do CORS para permitir requisições do front-end
# O URL do front-end é pego de uma variável de ambiente para flexibilidade
FRONTEND_URL = os.environ.get('FRONTEND_URL', '*')
CORS(app, resources={r"/*": {"origins": FRONTEND_URL}})

# Configuração do Banco de Dados a partir de uma URL de conexão (ideal para produção)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuração do JWT (JSON Web Tokens)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY') # Chave secreta forte
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=24) # Token expira em 24 horas

db = SQLAlchemy(app)
jwt = JWTManager(app)


# --- MODELOS DO BANCO DE DADOS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    records = db.relationship('Record', backref='owner', lazy=True, cascade="all, delete-orphan")

class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    album = db.Column(db.String(200), nullable=False)
    artist = db.Column(db.String(200), nullable=False)
    year = db.Column(db.Integer, nullable=True)
    cover_url = db.Column(db.String(500), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# --- ROTAS DA API ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('password') or not data.get('name'):
        return jsonify({'message': 'Dados incompletos fornecidos.'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Este email já está em uso.'}), 409
        
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(name=data['name'], email=data['email'], password_hash=hashed_password)
    
    try:
        db.session.add(new_user)
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
        
    user = User.query.filter_by(email=data['email']).first()
    
    if not user or not check_password_hash(user.password_hash, data['password']):
        return jsonify({'message': 'Credenciais inválidas.'}), 401
    
    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token)

# Rota protegida: Requer um token JWT válido
@app.route('/collection', methods=['GET'])
@jwt_required()
def get_collection():
    current_user_id = get_jwt_identity()
    records = Record.query.filter_by(user_id=current_user_id).order_by(Record.created_at.desc()).all()
    
    output = []
    for record in records:
        record_data = {
            'id': record.id, 'album': record.album, 'artist': record.artist,
            'year': record.year, 'cover_url': record.cover_url
        }
        output.append(record_data)
        
    return jsonify(output)

# Rota protegida: Requer um token JWT válido
@app.route('/records', methods=['POST'])
@jwt_required()
def add_record():
    current_user_id = get_jwt_identity()
    data = request.get_json()
    
    if not data or not data.get('album') or not data.get('artist'):
         return jsonify({'message': 'Álbum e Artista são obrigatórios.'}), 400
         
    new_record = Record(
        album=data['album'], artist=data['artist'], year=data.get('year'),
        cover_url=data.get('cover_url'), user_id=current_user_id
    )
    
    try:
        db.session.add(new_record)
        db.session.commit()
        return jsonify({'message': 'Disco adicionado com sucesso!', 'id': new_record.id}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Erro interno do servidor: {str(e)}'}), 500

if __name__ == '__main__':
    with app.app_context():
        # Cria as tabelas no banco de dados se elas não existirem
        db.create_all()
    # A porta é pega de uma variável de ambiente, padrão para 5000 localmente
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

