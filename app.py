import os
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from graficos import create_bar_chart, create_memory_chart  # Corrigido para importar ambas as funções
from server import app as server_app
# Carregar as variáveis do .env
load_dotenv()


# Testa se as variáveis estão carregadas
print("AUTH0_CLIENT_ID:", os.getenv("AUTH0_CLIENT_ID"))
print("AUTH0_CLIENT_SECRET:", os.getenv("AUTH0_CLIENT_SECRET"))
print("AUTH0_DOMAIN:", os.getenv("AUTH0_DOMAIN"))
print("APP_SECRET_KEY:", os.getenv("APP_SECRET_KEY"))


# Carregar as variáveis do .env
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Rota principal
@app.route('/')

def index():
    return render_template('index.html')



# Rota do gráfico 1 (Desempenho de Processadores)
@app.route('/index7')
def grafico1():
    graph_html = create_bar_chart()  # Gera o gráfico de barras do desempenho do processador
    return render_template('index7.html', graph_html=graph_html)


@app.route('/index6')
def grafico2():
    global percentual_memoria

    if percentual_memoria < 100:
        percentual_memoria += 5  # Aumenta 5% a cada recarregamento da página

    # Gerar o gráfico de memória
    graph_html = create_memory_chart()  # Função que gera o gráfico de velocidade de memória
    
    # Retornar a página com o gráfico de memória e a barra de progresso
    return render_template('index6.html', graph_html=graph_html, percentual=percentual_memoria)


# Outras rotas para páginas adicionais
@app.route('/index2')
def index2():
    return render_template('index2.html')

@app.route('/index3')
def index3():
    return render_template('index3.html')

@app.route('/index4')
def index4():
    return render_template('index4.html')

@app.route('/index5')
def index5():
    return render_template('index5.html')

@app.route('/index6')
def index6():
    return render_template('index6.html')

@app.route('/index7')
def index7():
    return render_template('index7.html')

@app.route('/index8')
def index8():
    return render_template('index8.html')

@app.route('/proccomp')
def proccomp():
    return render_template('proccomp.html')

@app.route('/home')
def home_page():
    return render_template('home.html')

@app.route('/login')
def login():
    return redirect(
        "https://dev-tw7648ler51b10s7.eu.auth0.com/authorize?response_type=code&client_id=g2xJF8I0C3CWAm9DicdayFUpHjXAQ0oI&redirect_uri=https://programacao-avancada-com-python-10794.vercel.app/login/callback"
    )


@app.route('/logout')
def logout():
    # Redireciona o usuário para o logout no Auth0
    return redirect(
        'https://dev-tw7648ler51b10s7.eu.auth0.com/v2/logout?returnTo=https://programacao-avancada-com-python-10794.vercel.app/login'
    )



# Endpoint para criação de usuários (POST)
@app.route('/usuarios', methods=['POST'])
def criar_usuario():
    dados = request.json
    if not dados or 'email' not in dados or 'password' not in dados or 'nome' not in dados:
        return jsonify({"erro": "Dados incompletos"}), 400
    
    # Aqui você pode adicionar lógica para criar usuários sem Firebase
    new_user = {
        'Email': dados['email'],
        'pass': generate_password_hash(dados['password']),
        'Nome': dados['nome'],
        'role': 'user',
        'CreatedAt': 'dummy_timestamp',  # Substitua por lógica de timestamp se necessário
        'lastLogin': 'dummy_timestamp',   # Substitua por lógica de timestamp se necessário
        'Foto perfil': dados.get('foto_perfil', '')
    }
    
    return jsonify({"mensagem": "Usuário criado com sucesso", "id": "dummy_id"}), 201

# Endpoint para obter um usuário por ID (GET)
@app.route('/usuarios/<id>', methods=['GET'])
def obter_usuario(id):
    # Aqui você pode adicionar lógica para obter usuários sem Firebase
    return jsonify({"erro": "Usuário não encontrado"}), 404

if __name__ == '_main_':
    app.run(debug=True)