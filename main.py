# вариант1 AES
import json
import argparse
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def padding_text(source_text: str) -> bytes:
    '''
       Выполняем генерацию ключа для симметричного алгоритма.
       Генерацию ключей для ассиметричного алгоритма.
       Сериализацию ассиметричных ключей.
       Зашифрование ключа симметричного шифрования открытым ключом и сохранение по указанному пути.

       Parameters
       ----------
            text : bytes
               Сообщение, которое будем дополнять.
               Длина сообщения станет кратна длине шифркуемого блока.
       Returns
       -------
           bytes:
               Объект класса bytes.
    '''
    padder = padding.ANSIX923(32).padder()
    text = bytes(source_text, 'UTF-8')
    padded_text = padder.update(text) + padder.finalize()
    return padded_text


def hybrid_key_generation(settings: dict) -> None:
    '''
    Выполняем генерацию ключа для симметричного алгоритма.
    Генерацию ключей для ассиметричного алгоритма.
    Сериализацию ассиметричных ключей.
    Зашифрование ключа симметричного шифрования открытым ключом и сохранение по указанному пути.

    Parameters
    ----------
         settings : dict
            Cловарь, в который записываются пути до файлов.
    Returns
    -------
        None:
            Ничего не возвращаем.
    '''
    # генерация ключа симметричного алгоритма шифрования
    key = os.urandom(32)  # это байты

    print(type(key))
    print(key)

    # генерация пары ключей для асимметричного алгоритма шифрования
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()

    print(type(private_key))
    print(private_key)
    print(type(public_key))
    print(public_key)

    # сериализация открытого ключа в файл
    public_pem = 'public.pem'
    with open(public_pem, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    settings['public_key'] = public_pem

    # сериализация закрытого ключа в файл
    private_pem = 'private.pem'
    with open(private_pem, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    settings['secret_key'] = private_pem

    # зашифрование ключа симметричного шифрования открытым ключом
    symmetric_key_enc = public_key.encrypt(key,
                                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                             label=None))
    print(symmetric_key_enc)

    # сериализация ключа симмеричного алгоритма в файл
    file_name = 'symmetric.txt'
    with open(file_name, 'wb') as key_file:
        key_file.write(symmetric_key_enc)
    settings['symmetric_key'] = file_name



def hybrid_data_encryption(settings: dict) -> None:
    '''
    Расшифровка симметричного ключа.
    Зашифровка текста симметричным алгоритмом и сохранение по указанному пути.

    Parameters
    ----------
        data : dict
             Cловарь, в который записываются пути до файлов.
    Returns
    -------
        None:
            Ничего не возвращаем.
    '''


if __name__ == '__main__':
    settings = {
        'initial_file': 'path/to/inital/file.txt',
        'encrypted_file': 'path/to/encrypted/file.txt',
        'decrypted_file': 'path/to/decrypted/file.txt',
        'symmetric_key': 'path/to/symmetric/key.txt',
        'public_key': 'path/to/public/key.pem',
        'secret_key': 'path/to/secret/key.pem',
    }

    hybrid_key_generation(settings)

    # пишем в файл
    with open('settings.json', 'w') as fp:
        json.dump(settings, fp)
    # читаем из файла
    with open('settings.json') as json_file:
        json_data = json.load(json_file)

    print(json_data)
