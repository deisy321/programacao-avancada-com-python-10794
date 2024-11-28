from flask import Flask, render_template
import plotly.graph_objects as go

app = Flask(__name__)

# Função que gera o gráfico de barras (Desempenho dos Processadores)
def create_bar_chart():
    categories = [
        'Jogos de Alto Desempenho', 'Edição de Vídeo', 'Tarefas Cotidianas',
        'Design Gráfico', 'Portabilidade e Bateria', 'Aplicações em Nuvem', 
        'Computação de Baixa Potência'
    ]
    performance_scores = [90, 80, 70, 75, 60, 85, 55]
    
    fig = go.Figure(data=[go.Bar(
        x=categories, 
        y=performance_scores, 
        marker=dict(
            color=['rgba(0, 51, 102, 0.8)', 'rgba(204, 51, 0, 0.8)', 'rgba(0, 102, 51, 0.8)', 
                   'rgba(102, 0, 102, 0.8)', 'rgba(204, 153, 0, 0.8)', 'rgba(0, 102, 204, 0.8)', 
                   'rgba(51, 51, 51, 0.8)'],
            line=dict(color='rgba(0, 0, 0, 0.1)', width=1)
        )
    )])

    fig.update_layout(
        title="Desempenho dos Processadores em Diferentes Tarefas",
        xaxis_title="Categorias",
        yaxis_title="Pontuação de Desempenho",

        yaxis=dict(range=[0, 100], showgrid=False),  # Remover as linhas horizontais (gridlines)
        plot_bgcolor="white",  # Define o fundo branco do gráfico
        paper_bgcolor="white"  # Define o fundo branco fora do gráfico
    )
    
    return fig.to_html(full_html=False)

# Função que gera o gráfico de memória (Velocidade de Memória por Tipo)
def create_memory_chart():
    memory_types = ['RAM', 'ROM', 'Cache', 'Memória Flash', 'HDD', 'SSD']
    speeds = [3200, 150, 8000, 500, 120, 3000]

    fig = go.Figure(data=[go.Bar(
        x=memory_types, 
        y=speeds, 
        marker=dict(
            color=['rgba(0, 51, 102, 0.8)', 'rgba(204, 51, 0, 0.8)', 'rgba(0, 102, 51, 0.8)', 
                   'rgba(102, 0, 102, 0.8)', 'rgba(204, 153, 0, 0.8)', 'rgba(0, 102, 204, 0.8)'],
            line=dict(color=['rgba(0, 51, 102, 1)', 'rgba(204, 51, 0, 1)', 'rgba(0, 102, 51, 1)', 
                             'rgba(102, 0, 102, 1)', 'rgba(204, 153, 0, 1)', 'rgba(0, 102, 204, 1)'], width=1)
        )
    )])

    fig.update_layout(
        title="Velocidade de Memória por Tipo (em MB/s)",
        xaxis_title="Tipo de Memória",
        yaxis_title="Velocidade (em MB/s)",

        yaxis=dict(showgrid=False),  # Remover as linhas horizontais (gridlines)
        plot_bgcolor="white",  # Define o fundo branco do gráfico
        paper_bgcolor="white"  # Define o fundo branco fora do gráfico
    )
    
    return fig.to_html(full_html=False)



