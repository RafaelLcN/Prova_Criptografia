BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
def decode(encoded):
    """
    Decodifica uma string codificada em Base64 corretamente.
    """
    padding = encoded.count('=')
    encoded = encoded.rstrip('=')

    # Converte cada caractere Base64 em 6 bits
    binario = ''
    for char in encoded:
        index = BASE64_CHARS.find(char)
        if index == -1:
            raise ValueError(f"Caractere inválido na string Base64: '{char}'")
        binario += format(index, '06b')

    # Remove os bits extras adicionados durante o preenchimento
    if padding:
        binario = binario[:-(padding * 2)]

    # Divide em bytes de 8 bits
    bytes_resultado = []
    for i in range(0, len(binario), 8):
        byte = binario[i:i+8]
        if len(byte) == 8:
            bytes_resultado.append(int(byte, 2))

    # Converte para string
    return bytes(bytes_resultado).decode('utf-8')