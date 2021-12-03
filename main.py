# вариант1 AES
import json
import argparse
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def hybrid_key_generation(settings: dict) -> None:
    '''
    Выполняем генерацию ключа для симметричного алгоритма.
    Генерацию ключей для ассиметричного алгоритма.
    Сериализацию ассиметричных ключей.
    Зашифрование ключа симметричного шифрования открытым ключом и сохранение по указанному пути.

    Parameters
    ----------
         data : dict
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

    # сериализация ключа симмеричного алгоритма в файл
    file_name = 'symmetric.txt'
    with open(file_name, 'wb') as key_file:
        key_file.write(key)
    settings['symmetric_key'] = file_name

    # десериализация ключа симметричного алгоритма
    with open(file_name, mode='rb') as key_file:
        content = key_file.read()

    print(type(content))
    print(content)

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


