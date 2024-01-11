import sqlite3
import bcrypt

def hash_senha(senha):
    salt = bcrypt.gensalt()
    hashed_senha = bcrypt.hashpw(senha.encode('utf-8'), salt)
    return hashed_senha

conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY,
        nome TEXT,
        senha TEXT
    )
''')


senha_criptografada = hash_senha('teste')
cursor.execute('''
    INSERT INTO usuarios (nome, senha) VALUES (?, ?)
''', ('teste', senha_criptografada.decode('utf-8')))
conn.commit()
conn.close()
