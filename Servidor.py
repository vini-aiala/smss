import socket
import string
import sys
from time import sleep

from Crypto.Random import get_random_bytes

from Cifra import cria_cifra

TAMANHO_MAXIMO = 1443

ALGORITMOS = [0, 1, 2, 3, 4, 5]
MODOS = [0, 1, 2, 3, 4, 5]
PADDINGS = [0, 1]
CHARS = string.ascii_letters


class Servidor:
    def __init__(self, id, porta):
        self.id = id
        self.porta = porta

    def envia_bytes(self, msg_bytes):
        """Envia a mensagem msg. Deve estar no formato de bytes"""
        # print('Enviando a mensagem:', msg_bytes)

        meu_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET = IPV4, SOCK_STREAM = TCP
        server_address = ('localhost', self.porta + 1)
        meu_socket.connect(server_address)
        meu_socket.send(msg_bytes)
        meu_socket.close()

    def recebe_bytes(self):
        """Recebe a mensagem enviada por um cliente, retorna os bytes"""
        while True:
            # Criando o socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET = IPV4, SOCK_STREAM = TCP

            try:
                # O socket fica ouvindo o meio
                server_socket.bind(('', self.porta))
                server_socket.listen(1)

                while True:

                    # Aceita uma conexão
                    connection_socket, addr = server_socket.accept()

                    try:

                        # Recebe os dados e os decodifica
                        data = connection_socket.recv(TAMANHO_MAXIMO)
                        return data

                    except Exception as e:
                        print('Erro ao receber:', e)

            except Exception as e:
                print('Erro ao abrir o socket:', e)
                sleep(5)

    def processa_msg(self):
        """Recebe dados do cliente."""

        # Recebe msg
        print('\nAguardando nova mensagem...')
        msg = self.recebe_bytes()

        # Processa msg
        tipo = msg[0] & b'\x0f'[0]

        # Se não é um par_req nem lista, foi inesperado
        if tipo == 0:
            # Processa par_req
            try:
                origem = int.from_bytes(msg[1:3], 'big')
                print('Recebi a requisição dos parâmetros de', origem)
                destino = int.from_bytes(msg[3:5], 'big')
                algoritmo = msg[5] & b'\x0f'[0]
                padding = (msg[5] & b'\xf0'[0]) >> 4
                modo = msg[6]
            except Exception as e:
                print('Erro interno:', e)
                self.envia_parconf(2)
                return

            # Verifica se é destinatário
            if destino != self.id:
                print('Erro: Não sou o destinatário.')
                self.envia_parconf(2)
                return

            # Verifica se aceita parâmetros
            if (algoritmo in ALGORITMOS) & (padding in PADDINGS) & (modo in MODOS):
                iv = self.envia_parconf(0)
                print('Parâmetros Suportados!')
            else:
                self.envia_parconf(1)
                print('Erro: Parâmetros não suportados!')
                return

            # Recebe dados
            try:
                print('IV gerado:', iv)
                cifra = cria_cifra(algoritmo, modo, iv)
                dados = self.recebe_bytes()
                tipo = dados[0] & b'\x0f'[0]
                if tipo == 2:
                    erro = (dados[0] & b'\xf0'[0]) >> 4
                    if erro == 0:
                        criptografado = dados[3:]
                        descriptografado = cifra.decrypt(criptografado).decode("utf-8")
                        print('Dados recebidos:', criptografado, '→', descriptografado)
                        print('Enviando confirmação de envio...')
                        self.envia_conf(0)
                        return
                    else:
                        print("Erro no cliente:", erro)
                        return

                else:
                    # Se não é par_req nem lista, logo é inesperado.
                    print('Erro: Tipo inesperado.')
                    self.envia_conf(4)
            except Exception as e:
                print('Erro interno:', e)
                self.envia_conf(2)

        elif tipo == 3:
            pass
            return
        elif tipo == 5:
            sys.exit(0)
        else:
            # Se não é par_req nem lista, logo é inesperado.
            print('Erro: Tipo inesperado.')
            return

    def envia_parconf(self, erro):
        iv = get_random_bytes(16)
        par_conf = (1 | (erro << 4)).to_bytes(1, byteorder='big') + iv
        self.envia_bytes(par_conf)
        return iv

    def envia_conf(self, erro):
        conf = (4 | (erro << 4)).to_bytes(1, byteorder='big')
        self.envia_bytes(conf)
