import socket
import sys
from time import sleep

from Cifra import cria_cifra

TAMANHO_MAXIMO = 1443
tipo_dados = ['Dados', 'dados', 'd', 'D']
tipo_lista = ['Lista', 'lista', 'l', 'L']
tipo_sair = ['Sair', 'sair', 's', 'S']


class Cliente:
    def __init__(self, id, porta, servidor):
        self.id = id
        self.porta = porta
        self.servidor = servidor

    def envia_bytes(self, msg_bytes):
        """Envia a mensagem msg. Deve estar no formato de bytes"""
        # print('Enviando a mensagem:', bytes)

        meu_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET = IPV4, SOCK_STREAM = TCP
        server_address = ('localhost', self.porta)
        meu_socket.connect(server_address)
        meu_socket.send(msg_bytes)
        meu_socket.close()

    def recebe_bytes(self):
        """Recebe a mensagem enviada por um servidor, retorna os bytes"""
        while True:
            # Criando o socket
            connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # AF_INET = IPV4, SOCK_STREAM = TCP

            try:
                # O socket fica ouvindo o meio
                connection_socket.bind(('', self.porta + 1))
                connection_socket.listen(1)

                while True:

                    # Aceita uma conexão
                    connection_socket, addr = connection_socket.accept()

                    try:

                        # Recebe os dados e os decodifica
                        data = connection_socket.recv(TAMANHO_MAXIMO)
                        return data

                    except Exception as e:
                        print('Erro ao receber:', e)

            except Exception as e:
                print('Erro ao abrir o socket:', e)
                sleep(5)

    def envia_msg(self):
        """Envia uma string para o servidor."""

        tipo = input("\nQual o tipo de transmissão?\nOpções: (D)ados ou (S)air\n")
        if tipo in tipo_dados:
            dados = input('Digite a mensagem a ser enviada:\n')
            try:
                # Envia par_req
                tipo = (0 & b'\x0f'[0]).to_bytes(1, byteorder='big')
                origem = self.id.to_bytes(2, byteorder='big')
                destino = self.servidor.to_bytes(2, byteorder='big')
                algoritmo = int(input('Qual algoritmo a ser utilizado?\n'))
                padding = int(input('Qual padding a ser utilizado?\n'))
                alg_pad = (algoritmo | (padding << 4)).to_bytes(1, byteorder='big')
                modo = int(input('Qual modo a ser utilizado?\n')).to_bytes(1, byteorder='big')
                par_req = tipo + origem + destino + alg_pad + modo
                self.envia_bytes(par_req)
                print("Enviei a requisição dos parâmetros para o servidor", self.servidor)
            except Exception as e:
                print("Erro ao enviar a requisição dos parâmetros:", e)
                return

                # Recebe par_conf
            try:
                par_conf = self.recebe_bytes()
                tipo = par_conf[0] & b'\x0f'[0]
                if tipo != 1:
                    raise Exception('Tipo de mensagem inesperado: ' + str(tipo))

                erro = (par_conf[0] & b'\xf0'[0]) >> 4
                if erro != 0:
                    raise Exception('Erro no servidor: ' + str(erro))
                else:
                    print("Confirmação dos parâmetros recebida!")
            except Exception as e:
                print(e)
                return

            try:
                # Processa par_conf
                iv = par_conf[1:]
                print('IV recebido:', iv)
                cifra = cria_cifra(algoritmo, modo[0], iv)

                # Envia Dados
                if padding == 0:
                    criptografado = cifra.encrypt(dados.encode())
                else:
                    criptografado = cifra.encrypt(dados.encode())
                tipo_erro = (2 | (0 << 4)).to_bytes(1, byteorder='big')
                tamanho = len(criptografado).to_bytes(2, byteorder='big')
                msg_dados = tipo_erro + tamanho + criptografado
                print('Enviando mensagem criptografada:', dados, '→', criptografado)
                self.envia_bytes(msg_dados)
            except Exception as e:
                print("Erro enviando dados:", e)
                tipo_erro = (2 | (2 << 4)).to_bytes(1, byteorder='big')
                tamanho = (0).to_bytes(2, byteorder='big')
                msg_dados = tipo_erro + tamanho
                self.envia_bytes(msg_dados)
                return

            try:
                # Recebe conf
                conf = self.recebe_bytes()
                tipo = conf[0] & b'\x0f'[0]
                if tipo != 4:
                    raise Exception('Tipo de mensagem inesperado: ' + str(tipo))

                erro = (conf[0] & b'\xf0'[0]) >> 4
                if erro != 0:
                    raise Exception('Erro no servidor: ' + str(erro))
                else:
                    print('Confirmação de envio recebida!')
            except Exception as e:
                print(e)

        elif tipo in tipo_sair:
            self.envia_sair()
            sys.exit(0)

        else:
            raise Exception('Tipo de mensagem não reconhecido')

    def envia_sair(self):
        conf = (5).to_bytes(1, byteorder='big')
        self.envia_bytes(conf)
