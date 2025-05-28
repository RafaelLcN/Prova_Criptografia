def right_rotate(x, n):
    # Realiza um "right rotate" (rotação para a direita) de 32 bits em 'x' por 'n' posições.
    # O '>> n' desloca os bits para a direita.
    # O '<< (32 - n)' desloca os bits para a esquerda, trazendo de volta os bits "rotacionados".
    # O '& 0xFFFFFFFF' garante que o resultado permaneça dentro de 32 bits.
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def sum32(*args):
    # Soma uma quantidade variável de argumentos e garante que o resultado tenha 32 bits.
    # O '& 0xFFFFFFFF' mascara o resultado para que ele não exceda 32 bits,
    # simulando um overflow de 32 bits.
    return sum(args) & 0xFFFFFFFF

def ch(x, y, z):
    # Função de escolha (CH - Choice function) usada no SHA-256.
    # Se 'x' for 1, o resultado é 'y', caso contrário, é 'z'.
    # Isso é equivalente a (x AND y) XOR (NOT x AND z).
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    # Função de maioria (MAJ - Majority function) usada no SHA-256.
    # O bit de saída é 1 se pelo menos dois dos bits de entrada 'x', 'y', 'z' forem 1.
    return (x & y) ^ (x & z) ^ (y & z)

def sigma0(x):
    # Primeira função de compressão sigma minúscula (σ0) para a expansão da mensagem.
    # Combina três operações de rotação para a direita e um deslocamento para a direita.
    return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3)

def sigma1(x):
    # Segunda função de compressão sigma minúscula (σ1) para a expansão da mensagem.
    # Combina três operações de rotação para a direita e um deslocamento para a direita.
    return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10)

def capsigma0(x):
    # Primeira função de compressão sigma maiúscula (Σ0) para a compressão do bloco.
    # Combina três operações de rotação para a direita.
    return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)

def capsigma1(x):
    # Segunda função de compressão sigma maiúscula (Σ1) para a compressão do bloco.
    # Combina três operações de rotação para a direita.
    return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)

# Constantes SHA-256.
# São os primeiros 32 bits fracionais da raiz cúbica dos primeiros 64 números primos.
k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b,
    0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152,
    0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
    0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

# Valores de hash iniciais SHA-256 (H0).
# São os primeiros 32 bits fracionais da raiz quadrada dos primeiros 8 números primos.
H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

def pad_message(message):
    # Prepara a mensagem para processamento SHA-256 adicionando preenchimento.
    # 1. Converte a mensagem para uma string de bits.
    m_bin = ''.join(f'{ord(c):08b}' for c in message)
    # 2. Adiciona um bit '1' ao final da mensagem.
    m_bin += '1'
    # 3. Adiciona bits '0' até que o comprimento da mensagem seja 448 (mod 512).
    # Isso deixa espaço para o comprimento original da mensagem nos últimos 64 bits do bloco.
    while len(m_bin) % 512 != 448:
        m_bin += '0'
    # 4. Adiciona o comprimento original da mensagem (em bits) como um inteiro de 64 bits.
    m_bin += f'{len(message) * 8:064b}'
    # 5. Divide a mensagem preenchida em blocos de 512 bits.
    return [m_bin[i:i+512] for i in range(0, len(m_bin), 512)]

def parse_block(block):
    # Processa um bloco de 512 bits e o expande em 64 palavras de 32 bits (W[0] a W[63]).
    # 1. Os primeiros 16 palavras (W[0] a W[15]) são os próprios 32 bits do bloco.
    w = [int(block[i:i+32], 2) for i in range(0, 512, 32)]
    # 2. As palavras restantes (W[16] a W[63]) são calculadas usando as palavras anteriores
    # e as funções sigma0 e sigma1.
    for i in range(16, 64):
        s0 = sigma0(w[i - 15])
        s1 = sigma1(w[i - 2])
        w.append(sum32(w[i - 16], s0, w[i - 7], s1))
    return w

def compress_block(w, H):
    # Função principal de compressão SHA-256, que processa um bloco de 512 bits.
    # 'w' são as 64 palavras expandidas do bloco.
    # 'H' são os valores de hash intermediários (a, b, c, d, e, f, g, h).

    # Inicializa as variáveis de trabalho com os valores de hash atuais.
    a, b, c, d, e, f, g, h = H

    # Loop principal de 64 rodadas.
    for i in range(64):
        # Calcula T1: uma combinação de h, a função capsigma1 de e, a função ch de e,f,g,
        # a constante k[i] e a palavra w[i].
        T1 = sum32(h, capsigma1(e), ch(e, f, g), k[i], w[i])
        # Calcula T2: uma combinação da função capsigma0 de a e da função maj de a,b,c.
        T2 = sum32(capsigma0(a), maj(a, b, c))

        # Atualiza as variáveis de trabalho com base nos valores calculados.
        # As variáveis são "rotacionadas" e atualizadas.
        h, g, f, e, d, c, b, a = g, f, e, sum32(d, T1), c, b, a, sum32(T1, T2)

    # Adiciona os valores de hash finais do bloco aos valores de hash iniciais.
    # O resultado é uma lista de 8 valores de hash atualizados.
    return [sum32(x, y) for x, y in zip(H, [a, b, c, d, e, f, g, h])]

def sha256(message, output_type='hex'):
    # Função principal para calcular o hash SHA-256 de uma mensagem.
    # 1. Preenche a mensagem para estar em um formato compatível com SHA-256.
    blocks = pad_message(message)
    # 2. Copia os valores de hash iniciais para evitar modificar a lista original.
    H = H0[:]
    # 3. Itera sobre cada bloco processado.
    for block in blocks:
        # Expande o bloco em 64 palavras.
        w = parse_block(block)
        # Comprime o bloco, atualizando os valores de hash.
        H = compress_block(w, H)
    
    # 4. Formata e retorna o hash final.
    if output_type == 'bin':
        # Retorna o hash em formato binário (string de 256 bits).
        return ''.join(f'{h:032b}' for h in H)
    else:
        # Retorna o hash em formato hexadecimal (string de 64 caracteres).
        return ''.join(f'{h:08x}' for h in H)
