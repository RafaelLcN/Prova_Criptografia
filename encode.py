import os

# Tabela Base64 padrão
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def encode(palavra):
    """
    Codifica uma string em Base64 corretamente.
    """
    palavra_bytes = palavra.encode('utf-8')
    binario = ''
    for byte in palavra_bytes:
        binario += format(byte, '08b')

    # Divide em blocos de 6 bits
    encoded = ''
    for i in range(0, len(binario), 6):
        bloco = binario[i:i+6]
        if len(bloco) < 6:
            bloco = bloco.ljust(6, '0')
        index = int(bloco, 2)
        encoded += BASE64_CHARS[index]

    # Adiciona "=" para múltiplos de 3 bytes
    resto = len(palavra_bytes) % 3
    if resto == 1:
        encoded += '=='
    elif resto == 2:
        encoded += '='

    return encoded



def gerar_assinatura(mensagem, chave_secreta="segredo"):
    """
    Gera uma assinatura simples da mensagem com base na soma dos valores ASCII dos caracteres.
    """
    total = 0
    for i, c in enumerate(mensagem + chave_secreta):
        total += (ord(c) * (i + 1)) % 256  # Peso simples baseado na posição
    return format(total % 65536, '04x')  # Retorna como hexadecimal de 4 dígitos
