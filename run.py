import os
import time
import hashlib
import binascii
import psutil
import multiprocessing
import logging
import sqlite3
from ecdsa import SigningKey, SECP256k1

try:
    from cryptography.fernet import Fernet
except ImportError:
    print("Module 'cryptography' is not installed. Install it using: pip install cryptography")
    exit()

# Логування
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Генерація ключа для шифрування приватних ключів
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

# Ініціалізація бази даних
def init_db():
    conn = sqlite3.connect('wallets.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS found_wallets (
                      address TEXT PRIMARY KEY, 
                      private_key TEXT)''')
    conn.commit()
    conn.close()

# Функція для запису в базу даних та у файл
def save_wallet(address, private_key):
    conn = sqlite3.connect('wallets.db')
    cursor = conn.cursor()
    encrypted_key = cipher.encrypt(private_key.encode())
    cursor.execute('INSERT OR IGNORE INTO found_wallets VALUES (?, ?)', (address, encrypted_key))
    conn.commit()
    conn.close()
    
    # Запис у файл
    with open("found_wallets.txt", "a") as f:
        f.write(f"Address: {address}, Private Key: {private_key}\n")
    
    logging.info(f"[SUCCESS] Wallet found! Address: {address}, Private Key: {private_key}")

# Генерація приватного ключа
def generate_private_key():
    return os.urandom(32).hex()

# Отримання публічного ключа
def private_key_to_public_key(private_key):
    sk = SigningKey.from_string(binascii.unhexlify(private_key), curve=SECP256k1)
    return sk.get_verifying_key().to_string().hex()

# Отримання адреси
def public_key_to_address(public_key):
    sha256 = hashlib.sha256(binascii.unhexlify(public_key)).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    versioned_payload = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    return encode_base58(versioned_payload + checksum)

# Кодер Base58
def encode_base58(b):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(b, 'big')
    result = ''
    while n > 0:
        n, remainder = divmod(n, 58)
        result = alphabet[remainder] + result
    return result

# Завантаження існуючих гаманців
def load_existing_wallets(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, 'r') as f:
        return set(line.strip() for line in f)

# Основна функція
def wallet_finder(existing_wallets):
    generated_count = 0
    start_time = time.time()
    
    while True:
        private_key = generate_private_key()
        public_key = private_key_to_public_key(private_key)
        address = public_key_to_address(public_key)
        generated_count += 1

        if address in existing_wallets:
            save_wallet(address, private_key)
            return  # Вихід після знаходження
        
        if generated_count % 500 == 0:
            elapsed_time = time.time() - start_time
            avg_speed = generated_count / elapsed_time if elapsed_time > 0 else 0
            cpu_load = psutil.cpu_percent(interval=1)
            logging.info(f"Generated: {generated_count}, Speed: {avg_speed:.2f} keys/sec, CPU: {cpu_load}%")

# Запуск процесів
def main():
    init_db()
    existing_wallets = load_existing_wallets('keys.txt')
    num_processes = os.cpu_count() // 2 or 1
    
    processes = []
    for _ in range(num_processes):
        p = multiprocessing.Process(target=wallet_finder, args=(existing_wallets,))
        processes.append(p)
        p.start()
    
    for p in processes:
        p.join()

if __name__ == "__main__":
    main()
