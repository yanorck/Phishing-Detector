# Verificador de Phishing

Um sistema avançado de detecção de phishing que combina múltiplas camadas de análise para identificar URLs potencialmente maliciosas.
Por Yan Vieira Romano - 7° Semestre Eng Comp Insper

## Estrutura do Projeto

```
Phishing-Detector/
├── app.py                 # Aplicação principal Flask
├── requirements.txt       # Dependências do projeto
├── .env.example          # Exemplo de configuração de variáveis de ambiente
├── modules/
│   ├── __init__.py
│   ├── api_checks.py     # Integração com APIs externas
│   ├── basic_checks.py   # Verificações básicas de URLs
│   ├── advanced_checks.py # Análises heurísticas avançadas
│   └── utils.py          # Funções utilitárias
├── static/
│   ├── images/           # Imagens e recursos estáticos
│   ├── script.js         # Lógica frontend
│   └── style.css         # Estilos da interface
└── templates/
    └── index.html        # Template principal
```

## Funcionalidades Implementadas

### Verificações Básicas (Conceito C)
- **Listas de Phishing Conhecidas**
  - Integração com Phishing Initiative para verificação em tempo real
  - Sistema de pontuação baseado em confirmações de phishing

- **Análise de Características Suspeitas**
  - Detecção de substituição de letras por números (ex: g00gle.com)
  - Identificação de uso excessivo de subdomínios
  - Análise de caracteres especiais suspeitos na URL

- **Interface Web**
  - Design legal
  - Tabela detalhada de resultados
  - Indicadores visuais de segurança
  - Sistema de alertas em tempo real

### Análise Heurística Avançada (Conceito B)
- **Verificação de Domínio**
  - Análise de idade do domínio via WHOIS
  - Detecção de DNS dinâmico (no-ip, dyndns)
  - Verificação de similaridade com marcas conhecidas, peguei a maioria brasileiras para ser útil no Brasil mesmo

- **Análise de Segurança**
  - Verificação completa de certificados SSL
  - Detecção de redirecionamentos suspeitos
  - Análise de conteúdo para formulários de login

- **Integração com APIs**
  - Google Safe Browsing
  - VirusTotal
  - URLScan.io
  - Phishing Initiative

### Sistema de Pontuação
- **Cálculo de Risco**
  - Pontuação baseada em múltiplos fatores
  - Pesos diferentes para cada tipo de verificação
  - Níveis de risco: Baixo, Médio, Alto, Muito Alto, Phishing Confirmado

### Interface Avançada
- **Visualização de Resultados**
  - Modal com detalhes completos de cada verificação
  - Formatação JSON para dados técnicos
  - Links diretos para relatórios externos

- **Feedback em Tempo Real**
  - Animações de carregamento
  - Atualização dinâmica de status
  - Alertas visuais para diferentes níveis de risco

## Requisitos
- Python 3.8+
- Flask
- Requests
- Validators
- Outras dependências listadas em requirements.txt

## Configuração
1. Clone o repositório
2. Instale as dependências: `pip install -r requirements.txt`
3. Copie `.env.example` para `.env` e configure suas chaves de API
4. Execute: `python app.py`

## Uso
1. Acesse a interface web
2. Insira a URL a ser verificada
3. Aguarde a análise completa
4. Consulte os resultados detalhados

