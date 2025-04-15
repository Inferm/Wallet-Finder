import os
import time
import hashlib
import binascii
import psutil
import multiprocessing
import logging
import sqlite3
import argparse
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

# Запис знайдених гаманців
def save_found_wallet(address, private_key):
    conn = sqlite3.connect('wallets.db')
    cursor = conn.cursor()
    encrypted_key = cipher.encrypt(private_key.encode())
    cursor.execute('INSERT OR IGNORE INTO found_wallets VALUES (?, ?)', (address, encrypted_key))
    conn.commit()
    conn.close()
    
    with open("found_wallets.txt", "a") as f:
        f.write(f"Address: {address}, Private Key: {private_key}\n")
    
    logging.info(f"[SUCCESS] Wallet found! Address: {address}, Private Key: {private_key}")

# Запис згенерованих гаманців кожні 10 хвилин
def save_generated_wallet(address, private_key):
    with open("generated_wallets.txt", "a") as f:
        f.write(f"Address: {address}, Private Key: {private_key}\n")
    logging.info(f"[GENERATED] New wallet - Address: {address}, Private Key: {private_key}")

# Генерація приватного ключа
def generate_private_key():
    return SigningKey.generate(curve=SECP256k1)

# Генерація Bitcoin-адреси з приватного ключа
def private_key_to_address(private_key):
    sk = private_key
    vk = sk.get_verifying_key()
    public_key = b'\x04' + vk.to_string()  # додано префікс 0x04 для неуніфікованого публічного ключа
    sha256 = hashlib.sha256(public_key).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    versioned_payload = b'\x00' + ripemd160  # Префікс 0x00 для P2PKH
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    binary_address = versioned_payload + checksum
    return encode_base58(binary_address)

# Base58
def encode_base58(b):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    n = int.from_bytes(b, 'big')
    result = ''
    while n > 0:
        n, remainder = divmod(n, 58)
        result = alphabet[remainder] + result
    leading_zeros = len(b) - len(b.lstrip(b'\x00'))
    return '1' * leading_zeros + result

# Завантаження існуючих адрес
def load_existing_wallets(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, 'r') as f:
        return set(line.strip() for line in f)

# Основна генерація
def wallet_generator(existing_wallets, process_id, max_cpu_percent):
    generated_count = 0
    start_time = time.time()
    last_save_time = start_time

    while True:
        private_key = generate_private_key()
        private_key_hex = private_key.to_string().hex()
        address = private_key_to_address(private_key)
        generated_count += 1
        
        if address in existing_wallets:
            save_found_wallet(address, private_key_hex)

        current_time = time.time()
        if current_time - last_save_time >= 600:
            save_generated_wallet(address, private_key_hex)
            last_save_time = current_time
            
            elapsed_time = current_time - start_time
            avg_speed = generated_count / elapsed_time if elapsed_time > 0 else 0
            cpu_load = psutil.cpu_percent(interval=1)
            print(f"Process {process_id} - Generated: {generated_count}, Speed: {avg_speed:.2f} keys/sec, CPU: {cpu_load}%")
        
        cpu_load = psutil.cpu_percent(interval=None)
        if cpu_load > max_cpu_percent:
            time.sleep(0.01)

# Точка входу
def main():
    parser = argparse.ArgumentParser(description="Bitcoin wallet generator with CPU load control")
    parser.add_argument('--max-cpu', type=float, default=80.0, help="Maximum CPU usage percentage (default: 80%)")
    args = parser.parse_args()
    
    max_cpu_percent = min(max(args.max_cpu, 10.0), 100.0)
    print(f"Max CPU usage set to: {max_cpu_percent}%")
    
    init_db()
    existing_wallets = load_existing_wallets('keys.txt')
    num_processes = os.cpu_count() or 1

    processes = []
    for i in range(num_processes):
        p = multiprocessing.Process(target=wallet_generator, args=(existing_wallets, i, max_cpu_percent))
        processes.append(p)
        p.start()
    
    for p in processes:
        p.join()

if __name__ == "__main__":
    main()
