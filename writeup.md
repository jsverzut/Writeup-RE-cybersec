O programa foi escrito com a biblioteca NCURSES, usada para construir interfaces em modo texto. Buscar por strings como "Username" e "Password" não retorna nada, o que indica que as strings do programa estão cifradas.

Entre as funções do NCURSES usadas estão `initscr()`, `endwin()`, `init_pair()`, `printw()` e `box()`. Olhando onde elas são chamadas, chega-se a `sub_8459`, uma função de ~5000 linhas descompiladas, cheia de checagens e funções stub usadas para ofuscar o fluxo. Logo no início, há uma checagem `if (initscr() == nullptr)` que decifra uma mensagem de erro via XOR sobre um array:

```c
if ( initscr() == nullptr )
{
    endwin();
    sub_2A08((int)v90);
    for ( a2 = 0; a2 <= 16; ++a2 )
    {
      LOBYTE(v55) = v60;
      v50[v55] = v60 ^ *(_BYTE *)(v48 + v49);
    }
    v50[v55] = 0;
    sub_29B6(v91);
    for ( i = 0; (unsigned int)i <= 13; ++i )
      v50[v55] ^= v79;
    v50[v55] = 0;
    fprintf(stderr, v50);
    exit(-1);
}
```

Esse mesmo padrão de decifragem por XOR se repete em várias partes do binário.

Buscando pelo uso de `strlen`, chega-se à função `sub_212A(a1: s, s: v798)`, que recebe duas strings vindas diretamente da entrada do usuário:

- `s = field_buffer(v802, 0)`
- `v798` é preenchido por `wgetch(stdscr)`

Essa é a função central de verificação, e passa a ser o foco da engenharia reversa.

A primeira parte de `sub_212A` verifica se a entrada (`s`) tem exatamente 29 caracteres e hífens nas posições 5, 11, 17 e 23:

```c
if ( strlen(s) != 29 )
    return 0;
memset(v19, 0, sizeof(v19));
k = 0;
m = 0;
while ( s[k] != 0 )
{
  if ( k == 5 || k == 11 || k == 17 || k == 23 )
  {
    if ( s[k] != '-' )
      return 0;
  }
```

Como nenhum username em `flag_maker.py` tem 29 caracteres, conclui-se que `s` corresponde à **senha**, e o segundo parâmetro (`a1`) ao **username**.

Em seguida, cada caractere não-hífen da senha é comparado contra um alfabeto gerado em tempo de execução:

```c
for ( i = 0; i <= 31; ++i )
{
	sub_20DA(a1: (int *)field_1B8_1);
	for ( a3 = 0; a3 <= 31; ++a3 )
	{
	  // buff[j+33] ^= buff[j]
	  v3 = (char *)sub_1B8D6(a1: (int)&field_1B8_1[33], a2: a3);
	  v17 = sub_1B8FA(a1: (int)field_1B8_1, a2: *v3, a3);
	  *(_BYTE *)sub_1B8D6(a1: (int)&field_1B8_1[33], a2: a3) = v17;
	}
	// buff[65] = '\0'
	*(_BYTE *)sub_1B8D6(a1: (int)&field_1B8_1[33], a2: 32) = '\0';
	v4 = (char *)sub_1B92A(a1: (int)&field_1B8_1[33]);
	// v19[k++] = i
	if ( v4[i] == s[j] )
	{
	  v5 = k / 5;
	  v6 = k++;
	  v19[5 * v5 + v6 % 5] = i;
	  v38 = 1;
	  break;
	}
}
```

`sub_20DA` inicializa o buffer `field_1B8_1` com valores retirados da memória no offset 1E200. O laço interno faz o XOR das duas metades de 33 bytes do buffer entre si. Ao final, obtém-se o alfabeto (é possível obter esse mesmo valor executando `secret.py`):

```
23456789ABCDEFGHJKLMNPQRSTUVWXYZ
```

Cada um dos 25 caracteres úteis da senha é mapeado para seu índice nesse alfabeto (0 a 31), e os índices são guardados em `v19`, organizada como uma matriz 5x5 (`v19[5*linha + coluna]`). Até aqui, a função verificou apenas o **formato** da senha.

Com `v19` preenchida, a função processa o username para derivar uma segunda matriz, que será comparada contra a da senha:

```c
v37 = 0;
v36 = dword_252E0;                 // 31337
memset(v18, 0, sizeof(v18));
v35 = 0;
v34 = 0;
for ( j = 0; ; j += 4 )
{
  v9 = strlen(s: username_a1);
  if ( j >= v9 )
    break;
  v33 = 0;
  for ( k = 0; k <= 3; ++k )
  {
    v7 = j + k;
    if ( v7 == strlen(s: username_a1) )
      break;
    v33 = (v33 << 7) | username_a1[j + k] & 0x7F;
  }
  for ( i = 0; i <= 2; ++i )
  {
    v22 = dword_25160[3 * (v36 % 32) + i];
    v37 = (2 * v37) | ((v33 & (1 << v22)) >> v22);
  }
  for ( i = 0; i <= 2; ++i )
  {
    v23 = dword_25160[3 * (v36 % 32) + i];
    v33 = (v33 >> (v23 + 1) << v23) | v33 & ((1 << v23) - 1);
  }
  v34 += 3;
  for ( i = 0; i <= (v37 & 7); ++i )
  {
    v8 = 8121 * v36 + 28411;
    v36 = v8 % 134456;
  }
  i = 0;
  while ( i <= 4 )
  {
    v18[16 * v35 + i++] = ~(_BYTE)v33 & 0x1F;
    v33 >>= 5;
  }
  ++v35;
}
```

O username é consumido em blocos de até 4 caracteres, empacotados em um valor de 28 bits (usando só os 7 bits baixos de cada caractere). Um LCG (`v36`, iniciado em 31337, atualizado por `(8121*v36+28411) % 134456`) escolhe, via uma tabela de 32 trios de posições de bit (`dword_25160`), quais 3 bits de cada bloco são extraídos para formar uma chave acumulada (`v37`). O número de avanços do LCG depende desses mesmos 3 bits, amarrando o estado do gerador ao conteúdo do username. Os 25 bits restantes de cada bloco viram uma coluna de 5 valores de 5 bits (invertidos bit a bit), formando a matriz `v18`.

Ao final do laço há uma checagem de consistência:

```c
if ( v34 > 32 || v35 <= 4 )
  return 0;
```

que restringe o username a 5–10 blocos (≈17–40 caracteres); com exatamente 5 blocos, `v18` é uma matriz quadrada 5x5.

Cada coluna de `v18` é cifrada com uma rede de Feistel de 13 rodadas, usando a chave acumulada `(v37, v34)`:

```c
for ( j = 0; j < v35; ++j )
{
  v31 = v18[j] | (32 * v18[j + 16]) | ((unsigned __int16)v18[j + 32] << 10) & 0xC00;
  v30 = (8 * v18[j + 48]) | ((int)v18[j + 32] >> 2) & 7 | (v18[j + 64] << 8);
  for ( k = 0; k <= 12; ++k )
  {
    v10 = v31 ^ ((unsigned __int16)(8 * v30) | (unsigned __int16)(v30 >> 12)) & 0x7FFF;
    v11 = ~((2 * v37) | (v37 >> (v34 - 1)));
    v24 = v10 ^ v11 & ((1 << v34) - 1);
    v31 = v30 & 0x7FFF;
    v30 = ((unsigned __int16)v10 ^ (unsigned __int16)(v11 & ((1 << v34) - 1))) & 0x7FFF;
  }
  v18[j] = v31 & 0x1F;
  v18[j + 16] = (v31 >> 5) & 0x1F;
  v18[j + 32] = v30 & 0x1C | (v31 >> 10) & 3;
  v18[j + 48] = (v30 >> 5) & 0x1F;
  v18[j + 64] = (v30 >> 10) & 0x1F;
}
```

A cada rodada, uma metade (`v31`) é combinada por XOR com uma rotação circular de 15 bits da outra metade (`v30`), e o resultado passa por mais um XOR com `v11`, uma constante derivada de `v37` e `v34` mascarada para `v34` bits. Os papéis de `v31` e `v30` são então trocados para a próxima rodada. Como `v11` é recalculada da mesma forma em toda rodada, ela funciona como uma chave fixa repetida 13 vezes. Após isso, temos:

```c
for ( j = 0; j <= 4; ++j )
{
  for ( k = 0; k <= 4; ++k )
    v19[5 * j + k] = dword_1E180[v19[5 * j + k]];
}
```

Onde cada célula de `v19` (0–31) é usada como índice em `dword_1E180`, uma S-box de 32 entradas, e substituída pelo valor correspondente. Depois:

```c
for ( j = 0; j <= 4; ++j )
{
  for ( k = 0; k <= 4; ++k )
    v19[5 * j + k] ^= dword_250E0[5 * j + k];
}
```

Cada célula resultante sofre XOR com a célula correspondente de `dword_250E0`, uma matriz constante de 25 valores embutida no binário.

```c
for ( j = 1; j <= 4; ++j )
{
  v26 = j - 1;
  v12 = alloca(16 * ((4 * j + 15) / 0x10u));
  v25 = &v15;
  v15 = 0;
  v13 = &v16;
  for ( ii = j - 2; ii >= 0; --ii )
    *v13++ = 0;
  for ( k = 0; k < j; ++k )
    v25[k] = v19[5 * j + k];
  for ( k = j; k <= 4; ++k )
    v19[5 * j + k - j] = v19[5 * j + k];
  for ( k = 5 - j; k <= 4; ++k )
    v19[5 * j + k] = v25[j - 5 + k];
}
```

A linha `j` de `v19` é rotacionada `j` posições à esquerda. Para cada linha: os `j` primeiros elementos são guardados em um buffer temporário (`v25`, via `v15`/`v16`), o restante da linha é deslocado `j` posições para a esquerda, e os elementos guardados são recolocados no final, completando a rotação circular.

```c
for ( j = 0; j <= 4; ++j )
{
  for ( k = 0; k < v35; ++k )
  {
    v27 = 0;
    for ( i = 0; i <= 4; ++i )
      v27 = (LOBYTE(v19[5 * i + k]) * LOBYTE(v18[16 * j + i]) + (_BYTE)v27) & 0x1F;
    if ( j == k && v27 != 1 || j != k && v27 != 0 )
      return 0;
  }
}
return 1;
```

O produto de matrizes `v18 × v19` módulo 32 precisa resultar na matriz identidade. Como `v18` vem do username e `v19` da senha, isso equivale a exigir que `v19` seja a **inversa** de `v18` módulo 32.

Além disso, o binário faz um `ptrace(PTRACE_TRACEME, ...)` ofuscado e grava o resultado em um flag global. Em vez de encerrar o programa, esse flag muda silenciosamente a inicialização de `dword_250E0` (XOR `2` sem debugger, `4` com debugger) e de `dword_25160` (troca índices 0/1 sem debugger, 1/2 com debugger), corrompendo a lógica do algoritmo sob debugger.

Os keygens (`angr` e `z3`) replicam manualmente o caminho "sem debugger": XOR `2` em `dword_250E0` e troca dos índices 0/1 em cada trio de `dword_25160`.

Com o algoritmo mapeado, a geração das 50 senhas (uma por username do desafio) foi automatizada de duas formas.

A  versão utilizada na apresentação, adaptada do script de [deadmoo83](https://gist.github.com/deadmoo83), baseia-se em `angr` para executar o binário simbolicamente a partir da função de verificação, simbolizando a senha e deixando o solver encontrar os 25 valores que levam ao caminho de sucesso. Os detalhes dessa abordagem estão documentados separadamente em [angr](angr).

A segunda abordagem, que iríamos utilizar, mas não o fizemos porque ela não fornecia corretamente todas as senhas, reimplementa o algoritmo inteiro em Python puro e usa o `z3` apenas para resolver o sistema de 25 equações (o produto de matrizes = identidade), evitando implementar manualmente a inversão de matriz módulo 32.

```python
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

print("CTF{" + hashlib.sha1(b"|".join(f"{u}:{p}".encode() for u, p in pairs)).hexdigest() + "}")
```

O script lê das tabelas extraídas do binário o alfabeto, os trios de bits, a S-box e a chave XOR, já aplicando o ajuste "sem debugger" descrito acima. Em seguida, calcula diretamente em Python a matriz do username (LCG e Feistel, que não dependem da senha), e modela os 25 valores desconhecidos da matriz da senha como variáveis simbólicas no `z3`, escrevendo a condição `V × T ≡ I (mod 32)` diretamente como equações sobre essas variáveis, já incorporando a rotação de linhas na própria formulação. O `z3` resolve o sistema e devolve os 25 valores, que passam pelo XOR inverso e pela S-box inversa antes de serem mapeados de volta pelo alfabeto, reconstruindo a senha de cada um dos 50 usuários. Concatenando os pares usuário:senha e calculando o SHA1, obtém-se a flag final.