#!/usr/bin/env python3
import hashlib
import re
import struct

from z3 import BitVec, BitVecVal, Solver, sat

# Alfabeto de 32 caracteres
with open("utils/buffer.bin", "rb") as f:
    raw = f.read()
ALPHABET = "".join(chr(raw[i] ^ raw[i + 33]) for i in range(32))

# 32 trios de posicoes de bits
with open("utils/dword_25160.bin", "rb") as f:
    TRIOS = list(struct.unpack("<96I", f.read(96 * 4)))

# Anti-debug: troca indices 0 e 1
for i in range(0, 96, 3):
    TRIOS[i], TRIOS[i + 1] = TRIOS[i + 1], TRIOS[i]

# Chave 5x5 sem debugger (XOR 2)
with open("utils/dword_250E0.bin", "rb") as f:
    KEY = [x ^ 2 for x in struct.unpack("<25I", f.read(25 * 4))]

# S-box e inversa
with open("utils/dword_1E180.bin", "rb") as f:
    SBOX = list(struct.unpack("<32I", f.read(32 * 4)))
INV_SBOX = [SBOX.index(i) for i in range(32)]


def username_matrix(user):
    """Deriva a matriz 5x5 do username."""
    v18 = [0] * 80
    key = blocks = keylen = 0
    state = 31337

    # Blocos de 4 caracteres
    for j in range(0, len(user), 4):
        x = 0
        for ch in user[j:j + 4]:
            x = (x << 7) | (ord(ch) & 0x7F)

        # Extrai 3 bits
        for i in range(3):
            q = TRIOS[3 * (state % 32) + i]
            key = (key << 1) | ((x >> q) & 1)

        # Remove os 3 bits usados
        for i in range(3):
            q = TRIOS[3 * (state % 32) + i]
            x = (x >> (q + 1) << q) | (x & ((1 << q) - 1))

        # Avanca o LCG
        for _ in range((key & 7) + 1):
            state = (8121 * state + 28411) % 134456

        # 25 bits restantes -> 5 valores
        for i in range(5):
            v18[16 * blocks + i] = ~x & 0x1F
            x >>= 5
        blocks += 1
        keylen += 3

    # Chave da Feistel
    mask = (1 << keylen) - 1
    fkey = ~(((key << 1) | (key >> (keylen - 1))) & mask) & mask

    # 13 rodadas por coluna
    for j in range(blocks):
        left = v18[j] | (v18[j + 16] << 5) | ((v18[j + 32] & 3) << 10)
        right = ((v18[j + 32] & 0x1C) >> 2) | (v18[j + 48] << 3) | (v18[j + 64] << 8)

        for _ in range(13):
            left, right = right & 0x7FFF, (
                left ^ (((right << 3) | (right >> 12)) & 0x7FFF) ^ fkey
            ) & 0x7FFF

        # Desempacota nos 5 valores
        v18[j] = left & 0x1F
        v18[j + 16] = (left >> 5) & 0x1F
        v18[j + 32] = ((left >> 10) & 3) | (right & 0x1C)
        v18[j + 48] = (right >> 5) & 0x1F
        v18[j + 64] = (right >> 10) & 0x1F

    # Matriz 5x5 final
    return [[v18[16 * j + i] for i in range(5)] for j in range(5)]


def solve(matrix):
    solver = Solver()

    # 25 variaveis de 5 bits
    W = [[BitVec(f"w{r}{c}", 5) for c in range(5)] for r in range(5)]

    # Condicao V * T == I (mod 32)
    for j in range(5):
        for k in range(5):
            total = BitVecVal(0, 5)
            for i in range(5):
                total += W[i][(k + i) % 5] * BitVecVal(matrix[j][i], 5)
            solver.add(total == BitVecVal(1 if j == k else 0, 5))

    if solver.check() != sat:
        return None

    # Desfaz XOR e S-box
    model = solver.model()
    rows = []
    for r in range(5):
        row = ""
        for c in range(5):
            w = model.eval(W[r][c], model_completion=True).as_long()
            row += ALPHABET[INV_SBOX[w ^ KEY[5 * r + c]]]
        rows.append(row)
    return "-".join(rows)


# Le os usernames
with open("utils/flag_maker.py", "r", encoding="utf-8") as f:
    users = re.findall(r"\('([^']+)',", f.read())

pairs = []
for user in users:
    password = solve(username_matrix(user))
    print(f"{user}: {password}")
    pairs.append((user, password))

print('CTF{' + hashlib.sha1(b'|'.join(f'{u}:{p}'.encode('utf-8') for u, p in pairs)).hexdigest() + '}')
