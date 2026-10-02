#!/usr/bin/env python3
"""
GCTF'23 - OldSchool: solver com angr (versão didática).

IDEIA GERAL
  O binário tem uma função que recebe (username, password) e diz se o par é
  válido. Em vez de rodar o programa inteiro (ncurses, anti-debug...), chamamos
  essa função diretamente no angr e fazemos assim:

    1. Rodamos de forma concreta até o ponto em que a senha ainda não foi
       misturada.
    2. Trocamos os 25 números da senha por símbolos (incógnitas).
    3. Pedimos ao angr: "ache valores para esses símbolos que levem ao ponto
       em que a senha é aceita".
    4. Convertemos os números achados de volta em texto (XXXXX-XXXXX-...).

COMO USAR
  Deixe 'oldschool' e 'flag_maker.py' na mesma pasta e rode:
      python3 angr_solve_simple.py
"""
import logging
import re

import angr
from angr import claripy

logging.getLogger("angr").setLevel("INFO")   # silencia logs do angr
logging.getLogger("cle").setLevel("CRITICAL")

# --------------------------------------------------------------------------
# Endereços (offsets em relação ao início do binário, que é PIE)
# --------------------------------------------------------------------------
FUNC_CHECK = 0x212A        # função que valida (username, password)
ADDR_BEFORE_MIX = 0x2747   # ponto logo antes de a senha ser misturada
ADDR_GOOD = 0x29A8         # ponto alcançado quando a senha é aceita
TABLE_XOR = 0x250E0        # tabela de 32 dwords alterada na inicialização
TABLE_FEISTEL = 0x25160    # 32 triplas de dwords alteradas na inicialização
PASSWORD_OFFSET = 0x114    # a senha fica em [ebp - 0x114], 25 ints de 4 bytes

# A senha usa só 32 símbolos (5 bits por caractere): sem 0, 1, I e O.
ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

# Carrega o binário uma única vez (carregar é lento).
proj = angr.Project("oldschool", auto_load_libs=False)
base = proj.loader.main_object.min_addr    # endereço onde o binário foi carregado
endian = proj.arch.memory_endness          # ordem dos bytes (little-endian no i386)


def prepare_tables(state):
    """
    Quando o programa roda sem debugger, ele altera duas tabelas antes de
    validar a senha. Como pulamos direto para a função de validação, temos
    que repetir essa inicialização na mão.
    """
    for i in range(32):
        # Tabela 1: cada valor passa por XOR com 2.
        addr = base + TABLE_XOR + 4 * i
        value = state.memory.load(addr, 4, endness=endian)
        state.memory.store(addr, value ^ 2, endness=endian)

        # Tabela 2: troca os dois primeiros dwords de cada tripla (12 bytes).
        addr = base + TABLE_FEISTEL + 12 * i
        first = state.memory.load(addr, 4, endness=endian)
        second = state.memory.load(addr + 4, 4, endness=endian)
        state.memory.store(addr, second, endness=endian)
        state.memory.store(addr + 4, first, endness=endian)


def run_until(state, offset):
    """Executa até o endereço base+offset. Devolve o estado, ou None se não chegar."""
    simgr = proj.factory.simgr(state)
    simgr.explore(find=base + offset)
    return simgr.found[0] if simgr.found else None


def solve(username):
    """Descobre a senha de um username. Devolve a senha, ou None se falhar."""
    # Passo 1: chamar a função de validação diretamente, com o username real e
    # uma senha qualquer que passe nas checagens iniciais (tamanho e formato).
    state = proj.factory.call_state(
        base + FUNC_CHECK,
        angr.PointerWrapper(username.encode() + b"\x00", buffer=True),
        angr.PointerWrapper(b"23456-789AB-CDEFG-HJKLM-NPQRS\x00", buffer=True),
        prototype="int c(char * u, char * p)",
        add_options=angr.options.unicorn,   # acelera a parte concreta
    )
    prepare_tables(state)

    # Passo 2: avançar até o ponto em que a senha começa a ser misturada.
    state = run_until(state, ADDR_BEFORE_MIX)
    if state is None:
        return None

    # Passo 3: trocar os 25 números da senha por símbolos de 5 bits.
    password_addr = state.solver.eval(state.regs.ebp) - PASSWORD_OFFSET
    symbols = []
    for i in range(25):
        sym = claripy.BVS(f"pw{i}", 32)             # incógnita de 32 bits
        state.solver.add(claripy.ULT(sym, 32))      # restrição: valor entre 0 e 31
        state.memory.store(password_addr + 4 * i, sym, endness=endian)
        symbols.append(sym)

    # Passo 4: pedir ao angr um caminho até o ponto "senha aceita".
    state = run_until(state, ADDR_GOOD)
    if state is None:
        return None

    # Passo 5: pegar os valores que o solver escolheu e virar texto.
    numbers = [state.solver.eval(sym) for sym in symbols]
    text = "".join(ALPHABET[n] for n in numbers)                  # 25 letras
    return "-".join(text[i:i + 5] for i in range(0, 25, 5))       # 5 grupos de 5


def main():
    source = open("flag_maker.py").read()

    # Os usernames são as strings que aparecem antes de '{password}' no arquivo.
    usernames = re.findall(r"\('(\w+)', '\{password\}'\)", source)

    for user in usernames:
        password = solve(user)
        if password is None:
            raise SystemExit(f"Não resolvido: {user}")
        print(user, password)

        # Coloca a senha no lugar do primeiro '{password}' ainda não preenchido.
        source = source.replace("{password}", password, 1)

    # O flag_maker.py, agora preenchido, imprime a flag ao ser executado.
    exec(source)


if __name__ == "__main__":
    main()
