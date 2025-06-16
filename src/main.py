import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import os
import base64
import webbrowser
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from collections import Counter
from datetime import datetime

class I18N:
    def __init__(self, language='en'):
        self.language = language
        self.translations = {
            'en': {
                'app_title': "CryptoSuite",
                'file': "File",
                'exit': "Exit",
                'help': "Help",
                'about': "About",
                'encrypt': "Encrypt",
                'decrypt': "Decrypt",
                'break_cipher': "Break Cipher",
                'key_management': "Key Management",
                'history': "History",
                'text_to_encrypt': "Text to Encrypt",
                'encryption_method': "Encryption Method:",
                'shift_key': "Shift Key:",
                'language': "Language:",
                'keyword': "Keyword:",
                'public_key_file': "Public Key File:",
                'browse': "Browse",
                'encrypt_btn': "Encrypt",
                'encrypted_result': "Encrypted Result",
                'export_result': "Export Result",
                'text_to_decrypt': "Text to Decrypt",
                'decryption_method': "Decryption Method:",
                'private_key_file': "Private Key File:",
                'password': "Password:",
                'decrypt_btn': "Decrypt",
                'decrypted_result': "Decrypted Result",
                'ciphertext_to_break': "Ciphertext to Break",
                'breaking_method': "Breaking Method:",
                'language_for_analysis': "Language for Analysis:",
                'break_cipher_btn': "Break Cipher",
                'break_results': "Break Results",
                'aes_key_mgmt': "AES Key Management",
                'generate_aes': "Generate New AES Key",
                'current_aes': "Current AES Key",
                'load_aes': "Load AES Key",
                'rsa_key_mgmt': "RSA Key Management",
                'generate_rsa': "Generate New RSA Key Pair",
                'save_rsa': "Save RSA Keys",
                'load_rsa_priv': "Load RSA Private Key",
                'load_rsa_pub': "Load RSA Public Key",
                'rsa_status': "RSA Status",
                'clear_history': "Clear History",
                'export_history': "Export History",
                'timestamp': "Timestamp",
                'operation': "Operation",
                'method': "Method",
                'operation_details': "Operation Details",
                'about_desc': "A comprehensive cryptography tool for encryption, decryption and cipher analysis.",
                'dev_info': "Developer Info",
                'github': "GitHub:",
                'open': "Open",
                'discord': "Discord:",
                'telegram': "Telegram:",
                'version': "Version 1.0.0",
                'warning': "Warning",
                'error': "Error",
                'success': "Success",
                'info': "Info",
                'confirm': "Confirm",
                'rsa_warning': "RSA Warning",
                'rsa_error': "RSA Error",
                'encryption_error': "Encryption Error",
                'decryption_error': "Decryption Error",
                'enter_to_encrypt': "Please enter a message to encrypt.",
                'caesarkey_int': "Caesar Cipher key must be an integer.",
                'vigenerekey_req': "Please enter a Vigenère key.",
                'aes_not_loaded': "AES key not generated/loaded. Generate or load a key in the 'Key Management' tab.",
                'rsa_pubkey_req': "Please provide the path to the RSA public key.",
                'rsa_too_long': "Message too long for RSA (max {max_bytes} bytes)",
                'rsa_encrypt_fail_size': "Could not encrypt with RSA due to message size.",
                'rsa_pubkey_not_found': "RSA public key not found at the specified path.",
                'rsa_encrypt_error': "Error encrypting with RSA: {e}",
                'invalid_method': "Invalid encryption method.",
                'enter_to_decrypt': "Please enter a message to decrypt.",
                'rsa_privkey_req': "Please provide the path to the RSA private key.",
                'rsa_privkey_not_found': "RSA private key not found at the specified path.",
                'rsa_pwd_invalid': "Incorrect password or invalid key format.",
                'rsa_decrypt_error': "Error decrypting with RSA: {e}. Check if the private key matches the ciphertext.",
                'enter_to_break': "Please enter the ciphertext to try breaking.",
                'rot13_break_result': "ROT13 is a Caesar cipher with key 13.\nDecrypted message:\n{result}",
                'unbreakable_info': ("\n--- ATTENTION ---\n"
                                     "AES and RSA are modern and robust cryptographic algorithms.\n"
                                     "Breaking them without the correct key is computationally infeasible with current resources.\n"
                                     "Any brute force attempt for AES/RSA would take billions of years.\n"
                                     "This program cannot 'break' these ciphers by security design."),
                'aes_key_generated': "New AES key generated: {key}\n\nCopy and save this key in a secure place!",
                'load_aes_key': "Load AES Key",
                'enter_aes_key': "Enter AES Key:",
                'aes_loaded_ok': "AES key loaded successfully!",
                'invalid_aes_key': "Invalid AES key: {e}",
                'rsa_keys_generated': "New RSA key pair generated successfully.",
                'no_rsa_to_save': "No RSA keys to save. Generate a key pair first.",
                'save_private_key_q': "Do you want to save the RSA private key?",
                'save_public_key_q': "Do you want to save the RSA public key?",
                'no_keys_selected': "No keys selected to save.",
                'save_rsa_priv_as': "Save RSA Private Key As",
                'save_rsa_pub_as': "Save RSA Public Key As",
                'protect_private_key_q': "Do you want to protect the private key with a password?",
                'private_key_password': "Private Key Password",
                'enter_password': "Enter password:",
                'no_pwd_set': "Password not set for private key.",
                'save_rsa_keys': "Save RSA Keys",
                'error_saving_keys': "An error occurred while saving keys: {e}",
                'key_password_q': "Does the private key have a password?",
                'load_rsa_priv_title': "Load RSA Private Key",
                'priv_key_loaded': "RSA private key loaded successfully.",
                'priv_key_not_found': "Private key file not found.",
                'pwd_or_format_error': "Incorrect password or invalid key format: {e}",
                'key_load_error': "An error occurred while loading the key: {e}",
                'load_rsa_pub_title': "Load RSA Public Key",
                'pub_key_loaded': "RSA public key loaded successfully.",
                'pub_key_not_found': "Public key file not found.",
                'rsa_status_priv': "Private Key Loaded.",
                'rsa_status_pub': "Public Key Loaded.",
                'rsa_status_none': "No key loaded/generated.",
                'history_empty': "History is already empty.",
                'clear_history_confirm': "Do you really want to clear all history?\nThis action cannot be undone.",
                'no_history_export': "No history to export.",
                'save_history_as': "Save history as",
                'history_exported': "History exported successfully!",
                'history_export_fail': "Failed to export history: {e}",
                'no_results_export': "No results to export.",
                'save_results_as': "Save results as",
                'results_exported': "Results exported successfully!",
                'results_export_fail': "Failed to export: {e}",
                'exit_prompt': "Do you really want to exit CryptoSuite?"
            },
            'pt': {
                'app_title': "CryptoSuite",
                'file': "Arquivo",
                'exit': "Sair",
                'help': "Ajuda",
                'about': "Sobre",
                'encrypt': "Criptografar",
                'decrypt': "Descriptografar",
                'break_cipher': "Quebrar Cifra",
                'key_management': "Gerenciar Chaves",
                'history': "Histórico",
                'text_to_encrypt': "Texto para Criptografar",
                'encryption_method': "Método de Criptografia:",
                'shift_key': "Chave de Deslocamento:",
                'language': "Idioma:",
                'keyword': "Palavra-chave:",
                'public_key_file': "Arquivo da Chave Pública:",
                'browse': "Procurar",
                'encrypt_btn': "Criptografar",
                'encrypted_result': "Resultado Criptografado",
                'export_result': "Exportar Resultado",
                'text_to_decrypt': "Texto para Descriptografar",
                'decryption_method': "Método de Descriptografia:",
                'private_key_file': "Arquivo da Chave Privada:",
                'password': "Senha:",
                'decrypt_btn': "Descriptografar",
                'decrypted_result': "Resultado Descriptografado",
                'ciphertext_to_break': "Texto Cifrado para Quebrar",
                'breaking_method': "Método de Quebra:",
                'language_for_analysis': "Idioma para Análise:",
                'break_cipher_btn': "Quebrar Cifra",
                'break_results': "Resultados da Quebra",
                'aes_key_mgmt': "Gerenciamento de Chave AES",
                'generate_aes': "Gerar Nova Chave AES",
                'current_aes': "Chave AES Atual",
                'load_aes': "Carregar Chave AES",
                'rsa_key_mgmt': "Gerenciamento de Chaves RSA",
                'generate_rsa': "Gerar Novo Par de Chaves RSA",
                'save_rsa': "Salvar Chaves RSA",
                'load_rsa_priv': "Carregar Chave Privada RSA",
                'load_rsa_pub': "Carregar Chave Pública RSA",
                'rsa_status': "Status RSA",
                'clear_history': "Limpar Histórico",
                'export_history': "Exportar Histórico",
                'timestamp': "Data e Hora",
                'operation': "Operação",
                'method': "Método",
                'operation_details': "Detalhes da Operação",
                'about_desc': "Uma ferramenta de criptografia para encriptação, decriptação e análise de cifras.",
                'dev_info': "Informações do Desenvolvedor",
                'github': "GitHub:",
                'open': "Abrir",
                'discord': "Discord:",
                'telegram': "Telegram:",
                'version': "Versão 1.0.0",
                'warning': "Aviso",
                'error': "Erro",
                'success': "Sucesso",
                'info': "Informação",
                'confirm': "Confirmar",
                'rsa_warning': "Aviso RSA",
                'rsa_error': "Erro RSA",
                'encryption_error': "Erro de Criptografia",
                'decryption_error': "Erro de Descriptografia",
                'enter_to_encrypt': "Por favor, insira uma mensagem para criptografar.",
                'caesarkey_int': "A chave da Cifra de César deve ser um número inteiro.",
                'vigenerekey_req': "Por favor, insira uma chave para Vigenère.",
                'aes_not_loaded': "A chave AES não foi gerada/carregada. Gere ou carregue uma chave na aba 'Gerenciar Chaves'.",
                'rsa_pubkey_req': "Por favor, forneça o caminho para a chave pública RSA.",
                'rsa_too_long': "Mensagem muito longa para RSA (máx. {max_bytes} bytes)",
                'rsa_encrypt_fail_size': "Não foi possível criptografar com RSA devido ao tamanho da mensagem.",
                'rsa_pubkey_not_found': "Chave pública RSA não encontrada no caminho especificado.",
                'rsa_encrypt_error': "Erro ao criptografar com RSA: {e}",
                'invalid_method': "Método de criptografia inválido.",
                'enter_to_decrypt': "Por favor, insira uma mensagem para descriptografar.",
                'rsa_privkey_req': "Por favor, forneça o caminho para a chave privada RSA.",
                'rsa_privkey_not_found': "Chave privada RSA não encontrada no caminho especificado.",
                'rsa_pwd_invalid': "Senha incorreta ou formato de chave inválido.",
                'rsa_decrypt_error': "Erro ao descriptografar com RSA: {e}. Verifique se a chave privada corresponde ao texto cifrado.",
                'enter_to_break': "Por favor, insira o texto cifrado para tentar quebrar.",
                'rot13_break_result': "ROT13 é uma cifra de César com chave 13.\nMensagem descriptografada:\n{result}",
                'unbreakable_info': ("\n--- ATENÇÃO ---\n"
                                     "AES e RSA são algoritmos de criptografia modernos e robustos.\n"
                                     "Quebrá-los sem a chave correta é computacionalmente inviável com os recursos atuais.\n"
                                     "Qualquer tentativa de força bruta para AES/RSA levaria bilhões de anos.\n"
                                     "Este programa não pode 'quebrar' essas cifras por design de segurança."),
                'aes_key_generated': "Nova chave AES gerada: {key}\n\nCopie e salve esta chave em um local seguro!",
                'load_aes_key': "Carregar Chave AES",
                'enter_aes_key': "Digite a Chave AES:",
                'aes_loaded_ok': "Chave AES carregada com sucesso!",
                'invalid_aes_key': "Chave AES inválida: {e}",
                'rsa_keys_generated': "Novo par de chaves RSA gerado com sucesso.",
                'no_rsa_to_save': "Não há chaves RSA para salvar. Gere um par de chaves primeiro.",
                'save_private_key_q': "Deseja salvar a chave privada RSA?",
                'save_public_key_q': "Deseja salvar a chave pública RSA?",
                'no_keys_selected': "Nenhuma chave selecionada para salvar.",
                'save_rsa_priv_as': "Salvar Chave Privada RSA Como",
                'save_rsa_pub_as': "Salvar Chave Pública RSA Como",
                'protect_private_key_q': "Deseja proteger a chave privada com uma senha?",
                'private_key_password': "Senha da Chave Privada",
                'enter_password': "Digite a senha:",
                'no_pwd_set': "Nenhuma senha definida para a chave privada.",
                'save_rsa_keys': "Salvar Chaves RSA",
                'error_saving_keys': "Ocorreu um erro ao salvar as chaves: {e}",
                'key_password_q': "A chave privada tem uma senha?",
                'load_rsa_priv_title': "Carregar Chave Privada RSA",
                'priv_key_loaded': "Chave privada RSA carregada com sucesso.",
                'priv_key_not_found': "Arquivo da chave privada não encontrado.",
                'pwd_or_format_error': "Senha incorreta ou formato de chave inválido: {e}",
                'key_load_error': "Ocorreu um erro ao carregar a chave: {e}",
                'load_rsa_pub_title': "Carregar Chave Pública RSA",
                'pub_key_loaded': "Chave pública RSA carregada com sucesso.",
                'pub_key_not_found': "Arquivo da chave pública não encontrado.",
                'rsa_status_priv': "Chave Privada Carregada.",
                'rsa_status_pub': "Chave Pública Carregada.",
                'rsa_status_none': "Nenhuma chave carregada/gerada.",
                'history_empty': "O histórico já está vazio.",
                'clear_history_confirm': "Você realmente deseja limpar todo o histórico?\nEsta ação não pode ser desfeita.",
                'no_history_export': "Não há histórico para exportar.",
                'save_history_as': "Salvar histórico como",
                'history_exported': "Histórico exportado com sucesso!",
                'history_export_fail': "Falha ao exportar histórico: {e}",
                'no_results_export': "Não há resultados para exportar.",
                'save_results_as': "Salvar resultados como",
                'results_exported': "Resultados exportados com sucesso!",
                'results_export_fail': "Falha ao exportar: {e}",
                'exit_prompt': "Você realmente deseja sair do CryptoSuite?"
            }
        }
    
    def get(self, key):
        return self.translations.get(self.language, {}).get(key, key)

class SimpleCiphers:
    LANG_FREQUENCIES = {
        'portuguese': {
            'a': 14.63, 'e': 12.57, 'o': 10.73, 's': 7.81, 'r': 6.53, 'i': 6.18, 'n': 5.07,
            'd': 4.96, 'm': 4.74, 'u': 4.63, 't': 4.34, 'c': 3.13, 'l': 2.78, 'p': 2.52,
            'h': 2.49, 'v': 1.67, 'q': 1.20, 'f': 1.02, 'z': 0.47, 'j': 0.40, 'x': 0.21,
            'k': 0.02, 'w': 0.01, 'y': 0.01
        },
        'english': {
            'e': 12.70, 't': 9.06, 'a': 8.17, 'o': 7.51, 'i': 6.97, 'n': 6.75, 's': 6.33,
            'h': 6.09, 'r': 5.99, 'd': 4.25, 'l': 4.03, 'u': 2.76, 'c': 2.78, 'm': 2.41,
            'w': 2.36, 'f': 2.23, 'g': 2.02, 'y': 1.97, 'p': 1.93, 'b': 1.29, 'v': 0.98,
            'k': 0.77, 'j': 0.15, 'x': 0.15, 'q': 0.10, 'z': 0.07
        }
    }

    @staticmethod
    def caesar_cipher(text, key, mode='encrypt'):
        result = []
        for char in text:
            if 'a' <= char <= 'z':
                base = ord('a')
                shifted = (ord(char) - base + (key if mode == 'encrypt' else -key)) % 26
                result.append(chr(base + shifted))
            elif 'A' <= char <= 'Z':
                base = ord('A')
                shifted = (ord(char) - base + (key if mode == 'encrypt' else -key)) % 26
                result.append(chr(base + shifted))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def vigenere_cipher(text, key, mode='encrypt'):
        result = []
        key_len = len(key)
        for i, char in enumerate(text):
            if char.isalpha():
                key_char = key[i % key_len].lower()
                shift = ord(key_char) - ord('a')
                if mode == 'decrypt':
                    shift = -shift
                
                if char.isupper():
                    base = ord('A')
                    shifted = (ord(char) - base + shift) % 26
                    result.append(chr(base + shifted))
                else:
                    base = ord('a')
                    shifted = (ord(char) - base + shift) % 26
                    result.append(chr(base + shifted))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def rot13_cipher(text, mode='encrypt'):
        return SimpleCiphers.caesar_cipher(text, 13, mode)

    @staticmethod
    def base64_encode(text):
        try:
            return base64.b64encode(text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error in Base64 encoding: {e}"

    @staticmethod
    def base64_decode(encoded_text):
        try:
            return base64.b64decode(encoded_text.encode('utf-8')).decode('utf-8')
        except Exception as e:
            return f"Error in Base64 decoding: {e}"

class CipherBreaker:
    @staticmethod
    def caesar_brute_force(ciphertext, language='english'):
        results = []
        best_score = -float('inf')
        best_key = -1
        best_decryption = ""

        for key in range(26):
            decrypted_text = SimpleCiphers.caesar_cipher(ciphertext, key, 'decrypt')
            score = CipherBreaker._calculate_frequency_score(decrypted_text, language)
            results.append((key, decrypted_text, score))
            
            if score > best_score:
                best_score = score
                best_key = key
                best_decryption = decrypted_text
        
        output = ["--- Brute Force Results ---"]
        for key, text, score in sorted(results, key=lambda x: x[2], reverse=True):
             output.append(f"Key {key} (Score: {-score:.2f}): {text[:70]}{'...' if len(text) > 70 else ''}")
        
        output.append("\n--- Best Result ---")
        if best_key != -1:
            output.append(f"Most probable key: {best_key}")
            output.append(f"Decrypted Text:\n{best_decryption}")
        else:
            output.append("No probable key found.")

        return "\n".join(output)

    @staticmethod
    def _calculate_frequency_score(text, language):
        clean_text = ''.join(filter(str.isalpha, text)).lower()
        if not clean_text:
            return -float('inf')

        letter_counts = Counter(clean_text)
        total_letters = sum(letter_counts.values())
        observed_freq = {char: (count / total_letters) * 100 for char, count in letter_counts.items()}
        expected_freq = SimpleCiphers.LANG_FREQUENCIES.get(language, {})
        
        if not expected_freq:
            return -float('inf')

        score = 0.0
        for char in expected_freq:
            expected = expected_freq.get(char, 0.0)
            observed = observed_freq.get(char, 0.0)
            score += (expected - observed) ** 2
            
        return -score

class AESCipher:
    def __init__(self, key=None):
        if key:
            if isinstance(key, str):
                key = key.encode('utf-8')
            self.key = base64.urlsafe_b64decode(key + b'=' * (4 - len(key) % 4)) if len(key) != 32 else key
        else:
            self.key = self._generate_key()
        self.cipher = Fernet(base64.urlsafe_b64encode(self.key))

    def _generate_key(self):
        return Fernet.generate_key()

    def encrypt(self, message):
        return self.cipher.encrypt(message.encode('utf-8')).decode('utf-8')

    def decrypt(self, encrypted_message):
        return self.cipher.decrypt(encrypted_message.encode('utf-8')).decode('utf-8')

    def get_key(self):
        return base64.urlsafe_b64encode(self.key).decode('utf-8')

class RSACipher:
    def __init__(self, private_key=None, public_key=None):
        self.private_key = private_key
        self.public_key = public_key

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def encrypt(self, message, public_key_obj, i18n):
        if not public_key_obj:
            raise ValueError("Public key not provided for encryption.")
        
        message_bytes = message.encode('utf-8')
        max_bytes = (public_key_obj.key_size // 8) - (2 * hashes.SHA256.digest_size) - 2

        if len(message_bytes) > max_bytes:
            return None, i18n.get('rsa_too_long').format(max_bytes=max_bytes)

        encrypted = public_key_obj.encrypt(
            message_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8'), None

    def decrypt(self, encrypted_message):
        if not self.private_key:
            raise ValueError("Private key not loaded for decryption.")

        encrypted_bytes = base64.b64decode(encrypted_message.encode('utf-8'))
        decrypted = self.private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted.decode('utf-8')

    def save_keys(self, private_path=None, public_path=None, password=None):
        messages = []
        if private_path and self.private_key:
            encryption = serialization.NoEncryption()
            if password:
                encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))

            with open(private_path, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=encryption
                ))
            messages.append(f"Private key saved to {private_path}")

        if public_path and self.public_key:
            with open(public_path, "wb") as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            messages.append(f"Public key saved to {public_path}")
        return "\n".join(messages)

    @staticmethod
    def load_private_key(path, password=None):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=password.encode('utf-8') if password else None,
                backend=default_backend()
            )

    @staticmethod
    def load_public_key(path):
        with open(path, "rb") as f:
            return serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

class CryptoGUI:
    def __init__(self, master):
        self.master = master
        self.i18n = I18N('en') 
        master.title(self.i18n.get('app_title'))
        master.geometry("1000x800")
        master.minsize(900, 700)
        
        self._setup_style()
        
        self.aes_cipher = None
        self.rsa_cipher = RSACipher()
        self.history = []
        
        self._create_menu()
        self._create_widgets()
        
        master.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_style(self):
        self.style = ttk.Style()
        self.colors = {
            'bg': '#121212', 'fg': '#e0e0e0', 'accent': '#4CAF50',
            'secondary': '#2196F3', 'surface': '#1e1e1e', 'error': '#f44336',
            'textfield': '#2d2d2d', 'highlight': '#FFC107', 'text': '#ffffff'
        }
        
        self.style.theme_use('clam')
        self.master.configure(bg=self.colors['bg'])
        
        self.style.configure('.', background=self.colors['bg'], foreground=self.colors['fg'], font=('Segoe UI', 10))
        self.style.configure('TButton', background=self.colors['surface'], foreground=self.colors['text'], borderwidth=0, padding=6)
        self.style.map('TButton', background=[('active', self.colors['accent'])], foreground=[('active', '#ffffff')])
        self.style.configure('TNotebook', background=self.colors['bg'], borderwidth=0)
        self.style.configure('TNotebook.Tab', background=self.colors['surface'], foreground=self.colors['text'], padding=[15, 5], font=('Segoe UI', 10, 'bold'))
        self.style.map('TNotebook.Tab', background=[('selected', self.colors['accent'])], foreground=[('selected', '#ffffff')])
        self.style.configure('Treeview', background=self.colors['textfield'], fieldbackground=self.colors['textfield'], foreground=self.colors['fg'])
        self.style.configure('Treeview.Heading', background=self.colors['surface'], foreground=self.colors['fg'], font=('Segoe UI', 9, 'bold'))
        self.style.map('Treeview', background=[('selected', self.colors['accent'])], foreground=[('selected', '#ffffff')])
        self.style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['text'])
        self.style.configure('TEntry', fieldbackground=self.colors['textfield'], foreground=self.colors['fg'], insertcolor=self.colors['fg'], borderwidth=1)
        self.style.configure('TCombobox', fieldbackground=self.colors['textfield'], foreground=self.colors['fg'], selectbackground=self.colors['accent'])
        self.style.configure('Accent.TButton', background=self.colors['secondary'])
        self.style.map('Accent.TButton', background=[('active', self.colors['accent'])])

    def _create_menu(self):
        menubar = tk.Menu(self.master)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label=self.i18n.get('exit'), command=self._on_close)
        menubar.add_cascade(label=self.i18n.get('file'), menu=file_menu)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label=self.i18n.get('about'), command=lambda: self.notebook.select(5))
        menubar.add_cascade(label=self.i18n.get('help'), menu=help_menu)
        
        self.master.config(menu=menubar)

    def _create_widgets(self):
        main_frame = ttk.Frame(self.master, padding="10")
        main_frame.pack(expand=True, fill='both')
        
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(expand=True, fill='both')
        
        self._setup_encrypt_tab(ttk.Frame(self.notebook))
        self._setup_decrypt_tab(ttk.Frame(self.notebook))
        self._setup_break_tab(ttk.Frame(self.notebook))
        self._setup_key_mgmt_tab(ttk.Frame(self.notebook))
        self._setup_history_tab(ttk.Frame(self.notebook))
        self._setup_about_tab(ttk.Frame(self.notebook))

    def _setup_encrypt_tab(self, frame):
        self.notebook.add(frame, text=self.i18n.get('encrypt'))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(4, weight=1)

        input_frame = ttk.LabelFrame(frame, text=self.i18n.get('text_to_encrypt'), padding=10)
        input_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(0, weight=1)
        
        self.encrypt_input_text = tk.Text(input_frame, height=8, bg=self.colors['textfield'], fg=self.colors['fg'], insertbackground=self.colors['fg'], bd=0, highlightthickness=1, highlightbackground='#333333')
        self.encrypt_input_text.grid(row=0, column=0, sticky='nsew')
        
        method_frame = ttk.Frame(frame)
        method_frame.grid(row=1, column=0, sticky='ew', pady=(0, 10))
        method_frame.columnconfigure(1, weight=1)
        
        ttk.Label(method_frame, text=self.i18n.get('encryption_method')).grid(row=0, column=0, sticky='w')
        self.encrypt_method = ttk.Combobox(method_frame, values=["Caesar Cipher", "Vigenère Cipher", "ROT13", "Base64", "AES", "RSA"], state='readonly')
        self.encrypt_method.set("Caesar Cipher")
        self.encrypt_method.grid(row=0, column=1, sticky='ew', padx=(5, 0))
        self.encrypt_method.bind("<<ComboboxSelected>>", self._on_encrypt_method_selected)
        
        self.encrypt_params_frame = ttk.Frame(frame)
        self.encrypt_params_frame.grid(row=2, column=0, sticky='ew', pady=(0, 10))
        
        self.encrypt_caesar_frame = ttk.Frame(self.encrypt_params_frame)
        ttk.Label(self.encrypt_caesar_frame, text=self.i18n.get('shift_key')).grid(row=0, column=0, padx=(0, 5), sticky='w')
        self.encrypt_caesar_key = ttk.Entry(self.encrypt_caesar_frame, width=5)
        self.encrypt_caesar_key.grid(row=0, column=1, sticky='w')
        
        self.encrypt_vigenere_frame = ttk.Frame(self.encrypt_params_frame)
        ttk.Label(self.encrypt_vigenere_frame, text=self.i18n.get('keyword')).grid(row=0, column=0, padx=(0, 5), sticky='w')
        self.encrypt_vigenere_key = ttk.Entry(self.encrypt_vigenere_frame)
        self.encrypt_vigenere_key.grid(row=0, column=1, sticky='ew')
        
        self.encrypt_rsa_key_frame = ttk.Frame(self.encrypt_params_frame)
        ttk.Label(self.encrypt_rsa_key_frame, text=self.i18n.get('public_key_file')).grid(row=0, column=0, padx=(0, 5), sticky='w')
        self.encrypt_rsa_public_key_path = ttk.Entry(self.encrypt_rsa_key_frame)
        self.encrypt_rsa_public_key_path.grid(row=0, column=1, sticky='ew')
        ttk.Button(self.encrypt_rsa_key_frame, text=self.i18n.get('browse'), command=self._browse_rsa_public_key_encrypt).grid(row=0, column=2, padx=(5, 0), sticky='e')
        
        self.encrypt_caesar_frame.pack(fill='x', expand=True)
        
        ttk.Button(frame, text=self.i18n.get('encrypt_btn'), command=self._perform_encryption).grid(row=3, column=0, pady=(5, 15))
        
        output_frame = ttk.LabelFrame(frame, text=self.i18n.get('encrypted_result'), padding=10)
        output_frame.grid(row=4, column=0, sticky='nsew')
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.encrypt_output_text = tk.Text(output_frame, height=8, state='disabled', bg=self.colors['textfield'], fg=self.colors['highlight'], bd=0, highlightthickness=1, highlightbackground='#333333')
        self.encrypt_output_text.grid(row=0, column=0, sticky='nsew')
        
        ttk.Button(frame, text=self.i18n.get('export_result'), command=lambda: self._export_results(self.encrypt_output_text)).grid(row=5, column=0, pady=(10, 0))

    def _setup_decrypt_tab(self, frame):
        self.notebook.add(frame, text=self.i18n.get('decrypt'))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(4, weight=1)
        
        input_frame = ttk.LabelFrame(frame, text=self.i18n.get('text_to_decrypt'), padding=10)
        input_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(0, weight=1)
        
        self.decrypt_input_text = tk.Text(input_frame, height=8, bg=self.colors['textfield'], fg=self.colors['fg'], insertbackground=self.colors['fg'], bd=0, highlightthickness=1, highlightbackground='#333333')
        self.decrypt_input_text.grid(row=0, column=0, sticky='nsew')
        
        method_frame = ttk.Frame(frame)
        method_frame.grid(row=1, column=0, sticky='ew', pady=(0, 10))
        method_frame.columnconfigure(1, weight=1)
        
        ttk.Label(method_frame, text=self.i18n.get('decryption_method')).grid(row=0, column=0, sticky='w')
        self.decrypt_method = ttk.Combobox(method_frame, values=["Caesar Cipher", "Vigenère Cipher", "ROT13", "Base64", "AES", "RSA"], state='readonly')
        self.decrypt_method.set("Caesar Cipher")
        self.decrypt_method.grid(row=0, column=1, sticky='ew', padx=(5, 0))
        self.decrypt_method.bind("<<ComboboxSelected>>", self._on_decrypt_method_selected)
        
        self.decrypt_params_frame = ttk.Frame(frame)
        self.decrypt_params_frame.grid(row=2, column=0, sticky='ew', pady=(0, 10))
        
        self.decrypt_caesar_frame = ttk.Frame(self.decrypt_params_frame)
        ttk.Label(self.decrypt_caesar_frame, text=self.i18n.get('shift_key')).grid(row=0, column=0, padx=(0, 5), sticky='w')
        self.decrypt_caesar_key = ttk.Entry(self.decrypt_caesar_frame, width=5)
        self.decrypt_caesar_key.grid(row=0, column=1, sticky='w')
        
        self.decrypt_vigenere_frame = ttk.Frame(self.decrypt_params_frame)
        ttk.Label(self.decrypt_vigenere_frame, text=self.i18n.get('keyword')).grid(row=0, column=0, padx=(0, 5), sticky='w')
        self.decrypt_vigenere_key = ttk.Entry(self.decrypt_vigenere_frame)
        self.decrypt_vigenere_key.grid(row=0, column=1, sticky='ew')
        
        self.decrypt_rsa_key_frame = ttk.Frame(self.decrypt_params_frame)
        ttk.Label(self.decrypt_rsa_key_frame, text=self.i18n.get('private_key_file')).grid(row=0, column=0, padx=(0, 5), sticky='w')
        self.decrypt_rsa_private_key_path = ttk.Entry(self.decrypt_rsa_key_frame)
        self.decrypt_rsa_private_key_path.grid(row=0, column=1, sticky='ew')
        ttk.Button(self.decrypt_rsa_key_frame, text=self.i18n.get('browse'), command=self._browse_rsa_private_key_decrypt).grid(row=0, column=2, padx=(5, 0), sticky='e')
        ttk.Label(self.decrypt_rsa_key_frame, text=self.i18n.get('password')).grid(row=1, column=0, padx=(0, 5), pady=(5, 0), sticky='w')
        self.decrypt_rsa_key_password = ttk.Entry(self.decrypt_rsa_key_frame, show="*")
        self.decrypt_rsa_key_password.grid(row=1, column=1, columnspan=2, sticky='ew', pady=(5, 0))
        
        self.decrypt_caesar_frame.pack(fill='x', expand=True)
        
        ttk.Button(frame, text=self.i18n.get('decrypt_btn'), command=self._perform_decryption).grid(row=3, column=0, pady=(5, 15))
        
        output_frame = ttk.LabelFrame(frame, text=self.i18n.get('decrypted_result'), padding=10)
        output_frame.grid(row=4, column=0, sticky='nsew')
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.decrypt_output_text = tk.Text(output_frame, height=8, state='disabled', bg=self.colors['textfield'], fg=self.colors['highlight'], bd=0, highlightthickness=1, highlightbackground='#333333')
        self.decrypt_output_text.grid(row=0, column=0, sticky='nsew')
        
        ttk.Button(frame, text=self.i18n.get('export_result'), command=lambda: self._export_results(self.decrypt_output_text)).grid(row=5, column=0, pady=(10, 0))

    def _setup_break_tab(self, frame):
        self.notebook.add(frame, text=self.i18n.get('break_cipher'))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(4, weight=1)
        
        input_frame = ttk.LabelFrame(frame, text=self.i18n.get('ciphertext_to_break'), padding=10)
        input_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(0, weight=1)
        
        self.break_input_text = tk.Text(input_frame, height=8, bg=self.colors['textfield'], fg=self.colors['fg'], insertbackground=self.colors['fg'], bd=0, highlightthickness=1, highlightbackground='#333333')
        self.break_input_text.grid(row=0, column=0, sticky='nsew')
        
        method_frame = ttk.Frame(frame)
        method_frame.grid(row=1, column=0, sticky='ew', pady=(0, 10))
        method_frame.columnconfigure(1, weight=1)
        
        ttk.Label(method_frame, text=self.i18n.get('breaking_method')).grid(row=0, column=0, sticky='w')
        self.break_method = ttk.Combobox(method_frame, values=["Caesar Cipher (Brute Force)", "Caesar Cipher (Frequency Analysis)", "ROT13", "AES/RSA (Unbreakable)"], state='readonly')
        self.break_method.set("Caesar Cipher (Frequency Analysis)")
        self.break_method.grid(row=0, column=1, sticky='ew', padx=(5, 0))
        self.break_method.bind("<<ComboboxSelected>>", self._on_break_method_selected)
        
        self.break_lang_frame = ttk.Frame(frame)
        ttk.Label(self.break_lang_frame, text=self.i18n.get('language_for_analysis')).grid(row=0, column=0, padx=(0, 5), sticky='w')
        self.break_caesar_lang = ttk.Combobox(self.break_lang_frame, values=["english", "portuguese"], width=15, state='readonly')
        self.break_caesar_lang.set("english")
        self.break_caesar_lang.grid(row=0, column=1, sticky='w')
        self.break_lang_frame.grid(row=2, column=0, sticky='ew', pady=(0, 10))
        
        ttk.Button(frame, text=self.i18n.get('break_cipher_btn'), command=self._perform_breaking).grid(row=3, column=0, pady=(5, 15))
        
        output_frame = ttk.LabelFrame(frame, text=self.i18n.get('break_results'), padding=10)
        output_frame.grid(row=4, column=0, sticky='nsew')
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(0, weight=1)
        
        self.break_output_text = tk.Text(output_frame, height=12, state='disabled', bg=self.colors['textfield'], fg=self.colors['highlight'], bd=0, highlightthickness=1, highlightbackground='#333333')
        self.break_output_text.grid(row=0, column=0, sticky='nsew')
        
        ttk.Button(frame, text=self.i18n.get('export_result'), command=lambda: self._export_results(self.break_output_text)).grid(row=5, column=0, pady=(10, 0))

    def _setup_key_mgmt_tab(self, frame):
        self.notebook.add(frame, text=self.i18n.get('key_management'))
        frame.columnconfigure(0, weight=1)
        
        aes_frame = ttk.LabelFrame(frame, text=self.i18n.get('aes_key_mgmt'), padding=15)
        aes_frame.grid(row=0, column=0, sticky='ew', pady=(10, 20), padx=10)
        aes_frame.columnconfigure(0, weight=1)
        
        ttk.Button(aes_frame, text=self.i18n.get('generate_aes'), command=self._generate_aes_key).grid(row=0, column=0, pady=(0, 10), sticky='ew')
        self.aes_current_key_label = ttk.Label(aes_frame, text=f"{self.i18n.get('current_aes')}: None", wraplength=700)
        self.aes_current_key_label.grid(row=1, column=0, pady=(0, 10), sticky='w')
        ttk.Button(aes_frame, text=self.i18n.get('load_aes'), command=self._load_aes_key_dialog).grid(row=2, column=0, pady=(0, 5), sticky='ew')
        
        rsa_frame = ttk.LabelFrame(frame, text=self.i18n.get('rsa_key_mgmt'), padding=15)
        rsa_frame.grid(row=1, column=0, sticky='ew', pady=(0, 20), padx=10)
        rsa_frame.columnconfigure(0, weight=1)
        
        ttk.Button(rsa_frame, text=self.i18n.get('generate_rsa'), command=self._generate_rsa_keys).grid(row=0, column=0, pady=(0, 10), sticky='ew')
        ttk.Button(rsa_frame, text=self.i18n.get('save_rsa'), command=self._save_rsa_keys_dialog).grid(row=1, column=0, pady=(0, 10), sticky='ew')
        ttk.Button(rsa_frame, text=self.i18n.get('load_rsa_priv'), command=self._load_rsa_private_key_dialog).grid(row=2, column=0, pady=(0, 10), sticky='ew')
        ttk.Button(rsa_frame, text=self.i18n.get('load_rsa_pub'), command=self._load_rsa_public_key_dialog).grid(row=3, column=0, pady=(0, 5), sticky='ew')
        
        self.rsa_status_label = ttk.Label(rsa_frame, text=f"{self.i18n.get('rsa_status')}: {self.i18n.get('rsa_status_none')}")
        self.rsa_status_label.grid(row=4, column=0, pady=(10, 0), sticky='w')

    def _setup_history_tab(self, frame):
        self.notebook.add(frame, text=self.i18n.get('history'))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(2, weight=1)

        control_frame = ttk.Frame(frame)
        control_frame.grid(row=0, column=0, sticky='ew', pady=(10, 10), padx=10)
        ttk.Button(control_frame, text=self.i18n.get('clear_history'), command=self._clear_history).pack(side='left')
        ttk.Button(control_frame, text=self.i18n.get('export_history'), command=self._export_history).pack(side='right')

        tree_frame = ttk.Frame(frame)
        tree_frame.grid(row=1, column=0, sticky='nsew', padx=10)
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        self.history_tree = ttk.Treeview(tree_frame, columns=('timestamp', 'operation', 'method'), show='headings')
        self.history_tree.heading('timestamp', text=self.i18n.get('timestamp'), anchor='w')
        self.history_tree.heading('operation', text=self.i18n.get('operation'), anchor='w')
        self.history_tree.heading('method', text=self.i18n.get('method'), anchor='w')
        self.history_tree.column('timestamp', width=180, stretch=False)
        self.history_tree.column('operation', width=120, stretch=False)
        self.history_tree.column('method', width=150)
        
        self.history_tree.grid(row=0, column=0, sticky='nsew')
        self.history_tree.bind('<<TreeviewSelect>>', self._on_history_select)
        
        details_frame = ttk.LabelFrame(frame, text=self.i18n.get('operation_details'), padding=10)
        details_frame.grid(row=2, column=0, sticky='nsew', pady=(10, 10), padx=10)
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)
        
        self.history_details = tk.Text(details_frame, wrap=tk.WORD, height=8, bg=self.colors['textfield'], fg=self.colors['fg'], insertbackground=self.colors['fg'], bd=0, highlightthickness=1, highlightbackground='#333333')
        self.history_details.grid(row=0, column=0, sticky='nsew')

    def _setup_about_tab(self, frame):
        self.notebook.add(frame, text=self.i18n.get('about'))
        container = ttk.Frame(frame, padding=20)
        container.pack(expand=True)
        
        ttk.Label(container, text=self.i18n.get('app_title'), font=('Segoe UI', 24, 'bold')).pack(pady=(0, 20))
        ttk.Label(container, text=self.i18n.get('about_desc'), wraplength=400, justify='center').pack(pady=(0, 30))
        
        dev_frame = ttk.LabelFrame(container, text=self.i18n.get('dev_info'), padding=15)
        dev_frame.pack(pady=(0, 20), fill='x')
        dev_frame.columnconfigure(1, weight=1)
        
        ttk.Label(dev_frame, text=self.i18n.get('github')).grid(row=0, column=0, sticky='w', pady=(0, 10))
        github_frame = ttk.Frame(dev_frame)
        ttk.Label(github_frame, text="yankkj", foreground=self.colors['secondary']).pack(side='left')
        ttk.Button(github_frame, text=self.i18n.get('open'), command=lambda: webbrowser.open("https://github.com/yankkj"), style='Accent.TButton').pack(side='left', padx=(10, 0))
        github_frame.grid(row=0, column=1, sticky='ew')
        
        ttk.Label(dev_frame, text=self.i18n.get('discord')).grid(row=1, column=0, sticky='w', pady=(0, 10))
        ttk.Label(dev_frame, text="imundar", foreground=self.colors['secondary']).grid(row=1, column=1, sticky='w')
        
        ttk.Label(dev_frame, text=self.i18n.get('telegram')).grid(row=2, column=0, sticky='w', pady=(0, 10))
        ttk.Label(dev_frame, text="feicoes", foreground=self.colors['secondary']).grid(row=2, column=1, sticky='w')
        
        ttk.Label(container, text=self.i18n.get('version'), font=('Segoe UI', 8)).pack(pady=(20, 0))

    def _on_encrypt_method_selected(self, event):
        selected_method = self.encrypt_method.get()
        for child in self.encrypt_params_frame.winfo_children():
            child.pack_forget()
        if selected_method == "Caesar Cipher":
            self.encrypt_caesar_frame.pack(fill='x', expand=True)
        elif selected_method == "Vigenère Cipher":
            self.encrypt_vigenere_frame.pack(fill='x', expand=True)
        elif selected_method == "RSA":
            self.encrypt_rsa_key_frame.pack(fill='x', expand=True)

    def _on_decrypt_method_selected(self, event):
        selected_method = self.decrypt_method.get()
        for child in self.decrypt_params_frame.winfo_children():
            child.pack_forget()
        if selected_method == "Caesar Cipher":
            self.decrypt_caesar_frame.pack(fill='x', expand=True)
        elif selected_method == "Vigenère Cipher":
            self.decrypt_vigenere_frame.pack(fill='x', expand=True)
        elif selected_method == "RSA":
            self.decrypt_rsa_key_frame.pack(fill='x', expand=True)

    def _on_break_method_selected(self, event):
        selected_method = self.break_method.get()
        if "Caesar Cipher" in selected_method:
            self.break_lang_frame.grid(row=2, column=0, sticky='ew', pady=(0, 10))
        else:
            self.break_lang_frame.grid_forget()

    def _browse_rsa_public_key_encrypt(self):
        file_path = filedialog.askopenfilename(title=self.i18n.get('load_rsa_pub_title'), filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if file_path:
            self.encrypt_rsa_public_key_path.delete(0, tk.END)
            self.encrypt_rsa_public_key_path.insert(0, file_path)

    def _browse_rsa_private_key_decrypt(self):
        file_path = filedialog.askopenfilename(title=self.i18n.get('load_rsa_priv_title'), filetypes=[("PEM files", "*.pem"), ("All files", "*.*")])
        if file_path:
            self.decrypt_rsa_private_key_path.delete(0, tk.END)
            self.decrypt_rsa_private_key_path.insert(0, file_path)

    def _perform_encryption(self):
        message = self.encrypt_input_text.get("1.0", tk.END).strip()
        method = self.encrypt_method.get()
        result = ""
        
        if not message:
            messagebox.showwarning(self.i18n.get('warning'), self.i18n.get('enter_to_encrypt'))
            return

        try:
            if method == "Caesar Cipher":
                key_str = self.encrypt_caesar_key.get()
                if not key_str.isdigit():
                    messagebox.showerror(self.i18n.get('error'), self.i18n.get('caesarkey_int'))
                    return
                result = SimpleCiphers.caesar_cipher(message, int(key_str), 'encrypt')
            elif method == "Vigenère Cipher":
                key = self.encrypt_vigenere_key.get()
                if not key:
                    messagebox.showerror(self.i18n.get('error'), self.i18n.get('vigenerekey_req'))
                    return
                result = SimpleCiphers.vigenere_cipher(message, key, 'encrypt')
            elif method == "ROT13":
                result = SimpleCiphers.rot13_cipher(message, 'encrypt')
            elif method == "Base64":
                result = SimpleCiphers.base64_encode(message)
            elif method == "AES":
                if not self.aes_cipher:
                    messagebox.showerror(self.i18n.get('error'), self.i18n.get('aes_not_loaded'))
                    return
                result = self.aes_cipher.encrypt(message)
            elif method == "RSA":
                rsa_public_key_path = self.encrypt_rsa_public_key_path.get()
                if not rsa_public_key_path:
                    messagebox.showerror(self.i18n.get('error'), self.i18n.get('rsa_pubkey_req'))
                    return
                try:
                    target_public_key = RSACipher.load_public_key(rsa_public_key_path)
                    encrypted_msg, warning_msg = self.rsa_cipher.encrypt(message, target_public_key, self.i18n)
                    if warning_msg:
                        messagebox.showwarning(self.i18n.get('rsa_warning'), warning_msg)
                        result = self.i18n.get('rsa_encrypt_fail_size')
                    else:
                        result = encrypted_msg
                except FileNotFoundError:
                    messagebox.showerror(self.i18n.get('rsa_error'), self.i18n.get('rsa_pubkey_not_found'))
                except Exception as e:
                    messagebox.showerror(self.i18n.get('rsa_error'), self.i18n.get('rsa_encrypt_error').format(e=e))
            else:
                messagebox.showerror(self.i18n.get('error'), self.i18n.get('invalid_method'))
        except Exception as e:
            messagebox.showerror(self.i18n.get('encryption_error'), f"An error occurred: {e}")

        self._update_output_text(self.encrypt_output_text, result)
        self._add_to_history('Encrypt', method, message, result)

    def _perform_decryption(self):
        message = self.decrypt_input_text.get("1.0", tk.END).strip()
        method = self.decrypt_method.get()
        result = ""

        if not message:
            messagebox.showwarning(self.i18n.get('warning'), self.i18n.get('enter_to_decrypt'))
            return

        try:
            if method == "Caesar Cipher":
                key_str = self.decrypt_caesar_key.get()
                if not key_str.isdigit():
                    messagebox.showerror(self.i18n.get('error'), self.i18n.get('caesarkey_int'))
                    return
                result = SimpleCiphers.caesar_cipher(message, int(key_str), 'decrypt')
            elif method == "Vigenère Cipher":
                key = self.decrypt_vigenere_key.get()
                if not key:
                    messagebox.showerror(self.i18n.get('error'), self.i18n.get('vigenerekey_req'))
                    return
                result = SimpleCiphers.vigenere_cipher(message, key, 'decrypt')
            elif method == "ROT13":
                result = SimpleCiphers.rot13_cipher(message, 'decrypt')
            elif method == "Base64":
                result = SimpleCiphers.base64_decode(message)
            elif method == "AES":
                if not self.aes_cipher:
                    messagebox.showerror(self.i18n.get('error'), self.i18n.get('aes_not_loaded'))
                    return
                result = self.aes_cipher.decrypt(message)
            elif method == "RSA":
                rsa_private_key_path = self.decrypt_rsa_private_key_path.get()
                rsa_private_key_password = self.decrypt_rsa_key_password.get() or None
                if not rsa_private_key_path:
                    messagebox.showerror(self.i18n.get('error'), self.i18n.get('rsa_privkey_req'))
                    return
                try:
                    loaded_private_key = RSACipher.load_private_key(rsa_private_key_path, rsa_private_key_password)
                    temp_rsa_cipher = RSACipher(private_key=loaded_private_key)
                    result = temp_rsa_cipher.decrypt(message)
                except FileNotFoundError:
                    messagebox.showerror(self.i18n.get('rsa_error'), self.i18n.get('rsa_privkey_not_found'))
                except ValueError:
                    messagebox.showerror(self.i18n.get('rsa_error'), self.i18n.get('rsa_pwd_invalid'))
                except Exception as e:
                    messagebox.showerror(self.i18n.get('rsa_error'), self.i18n.get('rsa_decrypt_error').format(e=e))
            else:
                messagebox.showerror(self.i18n.get('error'), self.i18n.get('invalid_method'))
        except Exception as e:
            messagebox.showerror(self.i18n.get('decryption_error'), f"An error occurred: {e}")

        self._update_output_text(self.decrypt_output_text, result)
        self._add_to_history('Decrypt', method, message, result)

    def _perform_breaking(self):
        ciphertext = self.break_input_text.get("1.0", tk.END).strip()
        method = self.break_method.get()
        language = self.break_caesar_lang.get()
        result = ""

        if not ciphertext:
            messagebox.showwarning(self.i18n.get('warning'), self.i18n.get('enter_to_break'))
            return

        if method == "Caesar Cipher (Brute Force)" or method == "Caesar Cipher (Frequency Analysis)":
            result = CipherBreaker.caesar_brute_force(ciphertext, language)
        elif method == "ROT13":
            decrypted_text = SimpleCiphers.rot13_cipher(ciphertext, 'decrypt')
            result = self.i18n.get('rot13_break_result').format(result=decrypted_text)
        elif method == "AES/RSA (Unbreakable)":
            result = self.i18n.get('unbreakable_info')
        else:
            messagebox.showerror(self.i18n.get('error'), "Invalid breaking method.")
        
        self._update_output_text(self.break_output_text, result)
        self._add_to_history('Break', method, ciphertext, result)

    def _generate_aes_key(self):
        self.aes_cipher = AESCipher()
        key = self.aes_cipher.get_key()
        self.aes_current_key_label.config(text=f"{self.i18n.get('current_aes')}: {key}")
        messagebox.showinfo(self.i18n.get('aes_key_generated').split(':')[0], self.i18n.get('aes_key_generated').format(key=key))

    def _load_aes_key_dialog(self):
        key = simpledialog.askstring(self.i18n.get('load_aes_key'), self.i18n.get('enter_aes_key'))
        if key:
            try:
                self.aes_cipher = AESCipher(key)
                self.aes_current_key_label.config(text=f"{self.i18n.get('current_aes')}: {key[:40]}...")
                messagebox.showinfo(self.i18n.get('success'), self.i18n.get('aes_loaded_ok'))
            except Exception as e:
                messagebox.showerror(self.i18n.get('error'), self.i18n.get('invalid_aes_key').format(e=e))

    def _generate_rsa_keys(self):
        self.rsa_cipher.generate_keys()
        messagebox.showinfo(self.i18n.get('rsa_keys_generated').split('.')[0], self.i18n.get('rsa_keys_generated'))
        self._update_rsa_status()

    def _save_rsa_keys_dialog(self):
        if not self.rsa_cipher.private_key:
            messagebox.showwarning(self.i18n.get('warning'), self.i18n.get('no_rsa_to_save'))
            return

        save_private = messagebox.askyesno(self.i18n.get('save_private_key_q').split('?')[0], self.i18n.get('save_private_key_q'))
        save_public = messagebox.askyesno(self.i18n.get('save_public_key_q').split('?')[0], self.i18n.get('save_public_key_q'))
        
        if not save_private and not save_public:
            return

        private_path, public_path, password = None, None, None
        
        if save_private:
            private_path = filedialog.asksaveasfilename(title=self.i18n.get('save_rsa_priv_as'), defaultextension=".pem", filetypes=[("PEM files", "*.pem")], initialfile="rsa_private_key.pem")
            if not private_path: save_private = False
        
        if save_public:
            public_path = filedialog.asksaveasfilename(title=self.i18n.get('save_rsa_pub_as'), defaultextension=".pem", filetypes=[("PEM files", "*.pem")], initialfile="rsa_public_key.pem")
            if not public_path: save_public = False
        
        if save_private and messagebox.askyesno(self.i18n.get('protect_private_key_q').split('?')[0], self.i18n.get('protect_private_key_q')):
            password = simpledialog.askstring(self.i18n.get('private_key_password'), self.i18n.get('enter_password'), show="*")
            if not password:
                messagebox.showinfo(self.i18n.get('warning'), self.i18n.get('no_pwd_set'))

        try:
            msg = self.rsa_cipher.save_keys(private_path, public_path, password)
            if msg: messagebox.showinfo(self.i18n.get('save_rsa_keys'), msg)
        except Exception as e:
            messagebox.showerror(self.i18n.get('error_saving_keys').split(':')[0], self.i18n.get('error_saving_keys').format(e=e))

    def _load_rsa_private_key_dialog(self):
        file_path = filedialog.askopenfilename(title=self.i18n.get('load_rsa_priv_title'), filetypes=[("PEM files", "*.pem")])
        if not file_path: return

        password = None
        if messagebox.askyesno(self.i18n.get('key_password_q').split('?')[0], self.i18n.get('key_password_q')):
            password = simpledialog.askstring(self.i18n.get('private_key_password'), self.i18n.get('enter_password'), show="*")
            
        try:
            loaded_key = RSACipher.load_private_key(file_path, password)
            self.rsa_cipher.private_key = loaded_key
            self.rsa_cipher.public_key = loaded_key.public_key()
            messagebox.showinfo(self.i18n.get('success'), self.i18n.get('priv_key_loaded'))
            self._update_rsa_status()
        except FileNotFoundError:
            messagebox.showerror(self.i18n.get('error'), self.i18n.get('priv_key_not_found'))
        except (ValueError, TypeError) as e:
            messagebox.showerror(self.i18n.get('error'), self.i18n.get('pwd_or_format_error').format(e=e))
        except Exception as e:
            messagebox.showerror(self.i18n.get('error'), self.i18n.get('key_load_error').format(e=e))

    def _load_rsa_public_key_dialog(self):
        file_path = filedialog.askopenfilename(title=self.i18n.get('load_rsa_pub_title'), filetypes=[("PEM files", "*.pem")])
        if file_path:
            try:
                self.rsa_cipher.public_key = RSACipher.load_public_key(file_path)
                messagebox.showinfo(self.i18n.get('success'), self.i18n.get('pub_key_loaded'))
                self._update_rsa_status()
            except FileNotFoundError:
                messagebox.showerror(self.i18n.get('error'), self.i18n.get('pub_key_not_found'))
            except Exception as e:
                messagebox.showerror(self.i18n.get('error'), self.i18n.get('key_load_error').format(e=e))

    def _update_rsa_status(self):
        status_parts = []
        if self.rsa_cipher.private_key:
            status_parts.append(self.i18n.get('rsa_status_priv'))
        if self.rsa_cipher.public_key:
            status_parts.append(self.i18n.get('rsa_status_pub'))
        
        status_text = f"{self.i18n.get('rsa_status')}: "
        if status_parts:
            status_text += " ".join(status_parts)
        else:
            status_text += self.i18n.get('rsa_status_none')
        self.rsa_status_label.config(text=status_text)

    def _add_to_history(self, op_type, method, input_text, output_text):
        entry = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'type': op_type,
            'method': method,
            'input': input_text,
            'output': output_text
        }
        self.history.insert(0, entry)
        if len(self.history) > 50:
            self.history.pop()
        self._update_history_tree()

    def _update_history_tree(self):
        self.history_tree.delete(*self.history_tree.get_children())
        for i, item in enumerate(self.history):
            self.history_tree.insert('', 'end', iid=str(i), values=(item['timestamp'], item['type'], item['method']))

    def _on_history_select(self, event):
        selected_item = self.history_tree.selection()
        if not selected_item: return
        
        index = int(selected_item[0])
        if 0 <= index < len(self.history):
            entry = self.history[index]
            details = (f"=== {entry['type']} Operation ===\n\n"
                       f"Timestamp: {entry['timestamp']}\n"
                       f"Method: {entry['method']}\n\n"
                       f"=== Input ===\n{entry['input']}\n\n"
                       f"=== Output ===\n{entry['output']}")
            self._update_output_text(self.history_details, details)

    def _clear_history(self):
        if not self.history:
            messagebox.showinfo(self.i18n.get('info'), self.i18n.get('history_empty'))
            return
        
        if messagebox.askyesno(self.i18n.get('confirm'), self.i18n.get('clear_history_confirm')):
            self.history.clear()
            self._update_history_tree()
            self._update_output_text(self.history_details, "")

    def _export_history(self):
        if not self.history:
            messagebox.showwarning(self.i18n.get('warning'), self.i18n.get('no_history_export'))
            return
        
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")], title=self.i18n.get('save_history_as'))
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    for entry in reversed(self.history):
                        f.write(f"--- Operation ---\n")
                        f.write(f"Timestamp: {entry['timestamp']}\n")
                        f.write(f"Type: {entry['type']}\n")
                        f.write(f"Method: {entry['method']}\n")
                        f.write(f"Input:\n{entry['input']}\n")
                        f.write(f"Output:\n{entry['output']}\n\n")
                messagebox.showinfo(self.i18n.get('success'), self.i18n.get('history_exported'))
            except Exception as e:
                messagebox.showerror(self.i18n.get('error'), self.i18n.get('history_export_fail').format(e=e))

    def _export_results(self, text_widget):
        content = text_widget.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning(self.i18n.get('warning'), self.i18n.get('no_results_export'))
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")], title=self.i18n.get('save_results_as'))
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo(self.i18n.get('success'), self.i18n.get('results_exported'))
            except Exception as e:
                messagebox.showerror(self.i18n.get('error'), self.i18n.get('results_export_fail').format(e=e))

    def _update_output_text(self, text_widget, content):
        text_widget.config(state='normal')
        text_widget.delete("1.0", tk.END)
        text_widget.insert(tk.END, content)
        text_widget.config(state='disabled')
        text_widget.see('1.0')

    def _on_close(self):
        if messagebox.askokcancel(self.i18n.get('exit'), self.i18n.get('exit_prompt')):
            self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()