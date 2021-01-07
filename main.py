import sys

from Cliente import Cliente
from Servidor import Servidor

PORTA = 50000
RA_VINICIUS = 59544
RA_GUILHERME = 20386
tipo_cliente = ['cliente', 'client', 'c']
tipo_servidor = ['servidor', 'server', 's']


def main():
    try:
        tipo = input('Qual o tipo do processo?\n')
        if tipo in tipo_cliente:
            cliente = Cliente(RA_GUILHERME, PORTA, RA_VINICIUS)
            while True:
                try:
                    cliente.envia_msg()
                except Exception as e:
                    print('Erro ao enviar: ', e)

        elif tipo in tipo_servidor:
            servidor = Servidor(RA_VINICIUS, PORTA)
            while True:
                try:
                    servidor.processa_msg()
                except Exception as e:
                    print('Erro ao receber: ', e)

        else:
            raise Exception('Tipo indefinido.')

    except Exception as e:
        print('Erro na função principal:', e)


if __name__ == "__main__":
    sys.exit(main())
