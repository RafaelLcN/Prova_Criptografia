import encodeSha256
import decode
import encode
import os


# Resposta exercício 3:
# O SHA-256 tem 64 rodadas internas. Aumentar esse número (para, por exemplo, 128) 
# tornaria cada cálculo de hash mais custoso, dificultando ataques massivos.
# Mais rodadas = mais segurança contra análise criptoanalítica e maior custo computacional para força bruta.

def criar_pacote():
    os.system('cls' if os.name == 'nt' else 'clear')
    mensagem = input('Digite a mensagem original: ')
    
    codificada = encode.encode(mensagem)
    assinatura = encodeSha256.sha256(mensagem, 's')

    # Junta codificada e assinatura, depois codifica tudo em Base64 novamente
    pacote = f'{codificada}.{assinatura}'
    pacote_final = encode.encode(pacote)

    # Salva o pacote codificado final em um arquivo
    with open('mensagem.txt', 'w', encoding='utf-8') as f:
        f.write(pacote_final)

    print('\nMensagem codificada:')
    print('Palavra original:', mensagem)
    print('Palavra codificada:', codificada)
    print('Assinatura SHA-256:', assinatura)
    print('\nPacote final (codificado em Base64):')
    print(pacote_final)


def verificar_pacote():
    os.system('cls' if os.name == 'nt' else 'clear')
    pacote_final = input('Cole o pacote recebido (todo codificado em Base64):\n')

    try:
        # Decodifica o pacote final para obter codificada.assinatura
        pacote = decode.decode(pacote_final)
    except Exception as e:
        print(f'\nErro ao decodificar o pacote Base64: {e}')
        return

    if '.' not in pacote:
        print('\n[ERRO] Pacote inválido! Deve conter uma assinatura separada por ponto.')
        return

    codificada, assinatura_recebida = pacote.split('.', 1)

    try:
        mensagem = decode.decode(codificada)
    except Exception as e:
        print(f'\nErro na decodificação Base64 da mensagem: {e}')
        return

    assinatura_calculada = encodeSha256.sha256(mensagem, 's')

    print('\nMensagem recebida:')
    print('Palavra codificada:', codificada)
    print('Palavra original:', mensagem)
    print('Assinatura recebida:', assinatura_recebida)
    print('Assinatura esperada:', assinatura_calculada)

    if assinatura_recebida == assinatura_calculada:
        print('\n Mensagem autêntica!')
    else:
        print('\n Mensagem adulterada!')


def menu():
    escolha = -1
    while escolha != 0:
        os.system('cls' if os.name == 'nt' else 'clear')
        print('===========================')
        print('1 - Codificar mensagem com assinatura')
        print('2 - Verificar pacote recebido')
        print('0 - Sair')
        print('===========================')

        try:
            escolha = int(input('Digite a opção: '))
        except ValueError:
            escolha = -1

        if escolha == 1:
            criar_pacote()
        elif escolha == 2:
            verificar_pacote()
        elif escolha == 0:
            print('Saindo...')
        else:
            print('Opção inválida!')

        if escolha != 0:
            input('\nPressione Enter para continuar...')

if __name__ == '__main__':
    menu()
