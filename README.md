# FastAPI JWT Authentication API

Uma API de autenticação desenvolvida com **FastAPI** que utiliza **JWT** (JSON Web Tokens) para autenticação e autorização de usuários.

<p align="center">
  <img src="https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/SQLAlchemy-FF0000?style=for-the-badge" alt="SQLAlchemy"/>
  <img src="https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=json-web-tokens" alt="JWT"/>
</p>

## 📑 Índice

- [FastAPI JWT Authentication API](#fastapi-jwt-authentication-api)
  - [📑 Índice](#-índice)
  - [✨ Funcionalidades](#-funcionalidades)
  - [🛠️ Tecnologias Utilizadas](#️-tecnologias-utilizadas)
  - [📂 Estrutura do Projeto](#-estrutura-do-projeto)
  - [🚀 Instalação e Configuração](#-instalação-e-configuração)
    - [Pré-requisitos](#pré-requisitos)
    - [Passos de Instalação](#passos-de-instalação)
  - [🎮 Como Usar](#-como-usar)
    - [Fluxo básico de uso:](#fluxo-básico-de-uso)
  - [📡 Endpoints da API](#-endpoints-da-api)
  - [📝 Exemplos de Uso](#-exemplos-de-uso)
    - [Registro de usuário](#registro-de-usuário)
    - [Login de usuário](#login-de-usuário)
    - [Acessando um endpoint protegido](#acessando-um-endpoint-protegido)
  - [🔒 Segurança](#-segurança)
  - [🤝 Contribuição](#-contribuição)

## ✨ Funcionalidades

- **Registro de usuários (Signup)**: Criação de novas contas com validação
- **Login de usuários (Signin)**: Autenticação e geração de token JWT
- **Proteção de rotas usando Bearer Token**: Middleware de autenticação
- **Hash de senhas para segurança**: Utilização de bcrypt para proteção das senhas
- **Middleware de autenticação**: Validação automática de tokens
- **Refresh token**: Renovação de tokens de acesso (na versão avançada)
- **Documentação interativa**: Interface Swagger e ReDoc automáticas

## 🛠️ Tecnologias Utilizadas

- **Python 3.11+**: Linguagem de programação backend
- **FastAPI**: Framework web de alta performance
- **SQLAlchemy**: ORM para interação com banco de dados
- **SQLite**: Banco de dados relacional leve
- **Uvicorn**: Servidor ASGI de alta performance
- **Python-Jose (PyJWT)**: Implementação de JWT
- **Passlib**: Biblioteca para hash de senhas
- **Pydantic**: Validação de dados e serialização

## 📂 Estrutura do Projeto

```
app/
├── main.py        # Inicializa a aplicação e define rotas
├── models.py      # Modelos do banco de dados (SQLAlchemy)
├── schemas.py     # Schemas de validação (Pydantic)
├── auth.py        # Funções de autenticação e segurança
├── database.py    # Configuração do banco de dados
└── config.py      # Configurações gerais da aplicação
```

## 🚀 Instalação e Configuração

### Pré-requisitos

- Python 3.11 ou superior
- pip (gerenciador de pacotes Python)

### Passos de Instalação

1. **Clone o repositório**:
   ```bash
   git clone https://github.com/seu-usuario/fastapi-jwt-authentication.git
   cd fastapi-jwt-authentication
   ```

2. **Crie e ative um ambiente virtual**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/MacOS
   # ou
   venv\Scripts\activate     # Windows
   ```

3. **Instale as dependências**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Execute o servidor**:
   ```bash
   uvicorn app.main:app --reload
   ```

5. **Acesse a documentação interativa**:
   - Swagger UI: [http://localhost:8000/docs](http://localhost:8000/docs)
   - ReDoc: [http://localhost:8000/redoc](http://localhost:8000/redoc)

## 🎮 Como Usar

Após iniciar o servidor, você pode interagir com a API usando o Swagger UI, ferramentas como Postman ou curl, ou qualquer biblioteca HTTP em sua aplicação.

### Fluxo básico de uso:

1. Registre um novo usuário com `/auth/register`
2. Faça login e obtenha um token JWT com `/auth/login`
3. Use este token no cabeçalho `Authorization: Bearer {seu_token}` para acessar rotas protegidas

## 📡 Endpoints da API

| Método | Endpoint | Descrição | Autenticação |
|--------|----------|-----------|--------------|
| GET | / | Endpoint raiz da API | Não |
| POST | /auth/register | Registrar novo usuário | Não |
| POST | /auth/login | Autenticar e obter token | Não |
| GET | /users/me | Obter dados do usuário atual | Sim |
| GET | /users | Listar todos os usuários | Sim |

## 📝 Exemplos de Uso

### Registro de usuário
```bash
curl -X POST "http://localhost:8000/auth/register" \
     -H "Content-Type: application/json" \
     -d '{"username": "usuario_teste", "email": "usuario@exemplo.com", "password": "senha123"}'
```

### Login de usuário
```bash
curl -X POST "http://localhost:8000/auth/login" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "username=usuario_teste&password=senha123"
```

### Acessando um endpoint protegido
```bash
curl -X GET "http://localhost:8000/users/me" \
     -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## 🔒 Segurança

Esta API implementa várias práticas de segurança:

- **Hashing de senhas**: Senhas nunca são armazenadas em texto puro
- **Tokens JWT assinados**: Prevenção contra adulteração de tokens
- **Expiração de tokens**: Tokens têm duração limitada
- **Validação de dados**: Todos os inputs são validados via Pydantic

## 🤝 Contribuição

Contribuições são bem-vindas! Para contribuir:

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova funcionalidade'`)
4. Push para a branch (`git push origin feature/nova-funcionalidade`)
5. Abra um Pull Request

---

<p align="center">Desenvolvido com ❤️ por Adam.</p>
