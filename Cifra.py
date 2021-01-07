from Crypto.Cipher import AES, DES3, DES

CHAVE_64 = b'chavinha'
CHAVE_128 = b'chave 1 de teste'
CHAVE_192 = b'chave 2 de teste grande!'
CHAVE_256 = b'chave 3 de teste muito grandona!'


def cria_cifra(algoritmo, modo, iv):
    # AES
    if algoritmo in range(0, 3):
        # Definição da chave baseada no parâmetro.
        chave = b''

        # AES128
        if algoritmo == 0:
            chave = CHAVE_128
        # AES192
        elif algoritmo == 1:
            chave = CHAVE_192
        # AES256
        elif algoritmo == 2:
            chave = CHAVE_256

        # Se for ECB
        if modo == 0:
            return AES.new(key=chave, mode=AES.MODE_ECB)

        # Se for CBC
        elif modo == 1:
            return AES.new(key=chave, mode=AES.MODE_CBC, iv=iv)

        # Se for CFB, precisamos especificar o S
        elif modo in range(2, 6):
            if modo == 2:
                return AES.new(key=chave, mode=AES.MODE_CFB, iv=iv, segment_size=1)
            elif modo == 3:
                return AES.new(key=chave, mode=AES.MODE_CFB, iv=iv, segment_size=8)
            elif modo == 4:
                return AES.new(key=chave, mode=AES.MODE_CFB, iv=iv, segment_size=64)
            elif modo == 5:
                return AES.new(key=chave, mode=AES.MODE_CFB, iv=iv, segment_size=128)

        # Se for counter
        elif modo == 6:
            raise Exception("Modo counter não suportado!")

    # DES
    if algoritmo in range(3, 4):
        # Se for ECB
        if modo in range(0, 1):
            return DES.new(key=CHAVE_64, mode=DES.MODE_ECB)

        # Se for CBC
        if modo in range(1, 2):
            return DES.new(key=CHAVE_64, mode=DES.MODE_CBC, iv=iv[0:8])

        # Se for CFB, precisamos especificar o S
        if modo in range(2, 6):
            if modo == 2:
                return DES.new(key=CHAVE_64, mode=DES.MODE_CFB, iv=iv[0:8], segment_size=1)
            elif modo == 3:
                return DES.new(key=CHAVE_64, mode=DES.MODE_CFB, iv=iv[0:8], segment_size=8)
            elif modo == 4:
                return DES.new(key=CHAVE_64, mode=DES.MODE_CFB, iv=iv[0:8], segment_size=64)
            else:
                return DES.new(key=CHAVE_64, mode=DES.MODE_CFB, iv=iv[0:8], segment_size=128)

        # Se for counter
        else:
            raise Exception("Modo counter não suportado!")

    # 3DES
    if algoritmo in range(4, 6):
        # Definição da chave baseada no parâmetro.
        chave = b''

        if algoritmo == 4:
            # DES3-EDE2
            chave = DES3.adjust_key_parity(CHAVE_128)
            pass
        if algoritmo == 5:
            # DES3-EDE3
            chave = DES3.adjust_key_parity(CHAVE_192)
            pass

        # Se for ECB
        if modo == 0:
            return DES3.new(key=chave, mode=DES3.MODE_ECB)

        # Se for CBC
        if modo == 1:
            return DES3.new(key=chave, mode=DES3.MODE_CBC)

        # Se for CFB, precisamos especificar o S
        if modo in range(2, 6):
            if modo == 2:
                # DES3128
                return DES3.new(key=chave, mode=DES3.MODE_CFB, iv=iv[0:8], segment_size=1)
            elif modo == 3:
                # DES3128
                return DES3.new(key=chave, mode=DES3.MODE_CFB, iv=iv[0:8], segment_size=8)
            elif modo == 4:
                # DES3128
                return DES3.new(key=chave, mode=DES3.MODE_CFB, iv=iv[0:8], segment_size=64)
            else:
                # DES3128
                return DES3.new(key=chave, mode=DES3.MODE_CFB, iv=iv[0:8], segment_size=128)

        # Se for counter
        else:
            raise Exception("Modo counter não suportado!")
