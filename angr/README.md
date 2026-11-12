```python
#!/usr/bin/env python3
# GCTF'23 - Old School - Flag Maker
import angr
import claripy
import hashlib
import logging

logging.getLogger("cle").setLevel("CRITICAL")
logging.getLogger("angr").setLevel("CRITICAL")

# Find the passwords for the following 50 usernames, substitute them inside the pairs,
# and then run the script to get the flag.
pairs = [
  ('gdwAnDgwbRVnrJvEqzvs', '{password}'),
  ('ZQdsfjHNgCpHYnOVcGvr', '{password}'),
  ('PmJgHBtIpaWNEMKiDQYW', '{password}'),
  ('OAmhVkxiUjUQWcmCCrVj', '{password}'),
  ('ALdgOAnaBbMwhbXExKrN', '{password}'),
  ('tqBXanGeFuaRSMDmwrAo', '{password}'),
  ('etTQMfSiRlMbNSuEOFZo', '{password}'),
  ('wceLFjLkBstBfQTtwnmv', '{password}'),
  ('rBiaRSHGLToSvIAQhZIs', '{password}'),
  ('ackTeRoASCkkkRUIBjmX', '{password}'),
  ('UBFLQMizCtLCnnOjaLMa', '{password}'),
  ('UwiBcAZEAJHKmZSrLqTB', '{password}'),
  ('oYlcWeZwpEEejIGuCHSU', '{password}'),
  ('txWHHXTtBXbckmRPxgCx', '{password}'),
  ('mhPdqEbAligcqQCsHLGl', '{password}'),
  ('UsIdCFPOqrXwsSMoqfIv', '{password}'),
  ('OdSAfswQJnMyjOlqpmqJ', '{password}'),
  ('eNKVZRlVwQCxWzDvUrUW', '{password}'),
  ('dUVNMmEPDxRIdVRXzbKa', '{password}'),
  ('iMBkfiyJxewhnvxDWXWB', '{password}'),
  ('xlQgeOrNItMzSrkldUAV', '{password}'),
  ('UPEfpiDmCeOzpXeqnFSC', '{password}'),
  ('ispoleetmoreyeah1338', '{password}'),
  ('dNcnRoRDFvfJbAtLraBd', '{password}'),
  ('FKBEgCvSeebMGixUVdeI', '{password}'),
  ('DfBrZwIrsHviSIbenmKy', '{password}'),
  ('OvQEEDVvxzZGSgNOhaEW', '{password}'),
  ('iNduNnptWlmAVsszvTIZ', '{password}'),
  ('GvTcyPNIUuojKfdqCbIQ', '{password}'),
  ('noAJKHffdaRrCDOpvMyj', '{password}'),
  ('rAViEUMTbUByuosLYfMv', '{password}'),
  ('YiECebDqMOwStHZyqyhF', '{password}'),
  ('phHkOgbzfuvTWVbvRlyt', '{password}'),
  ('arRzLiMFyEqSAHeemkXJ', '{password}'),
  ('jvsYsTpHxvXCxdVyCHtM', '{password}'),
  ('yOOsAYNxQndNLuPlMoDI', '{password}'),
  ('qHRTGnlinezNZNUCFUld', '{password}'),
  ('HBBRIZfprBYDWLZOIaAd', '{password}'),
  ('kXWLSuNpCGxenDxYyalv', '{password}'),
  ('EkrdIpWkDeVGOSPJNDVr', '{password}'),
  ('pDXIOdNXHhehzlpbJYGs', '{password}'),
  ('WMkwVDmkxpoGvuLvgESM', '{password}'),
  ('aUwdXCDDUWlPQwadOliF', '{password}'),
  ('WmlngotWTsikaXRDakbp', '{password}'),
  ('thrZhzSRBzJFPrxKmetr', '{password}'),
  ('TcurEDzLjepMrNwspPqd', '{password}'),
  ('SScTJRokTraQbzQpwDTR', '{password}'),
  ('PObUeTjQTwEflLQtPOJM', '{password}'),
  ('LUDPGXGvuVFAYlMTTowZ', '{password}'),
  ('UlTVDrBlCmXmFBmwLLKX', '{password}'),
]

total = len(pairs)

for index, pair in enumerate(pairs):
  pair_num = index + 1
  user, pw = pair

  # use the actual username
  username = user.encode()+b'\x00'
  username_ptr = angr.PointerWrapper(username, buffer=True)

  # use a dumb password that passes all the early sanity checks
  password = b'23456-789AB-CDEFG-HJKLM-NPQRS\x00'
  password_ptr = angr.PointerWrapper(password, buffer=True)
  
  # load the binary 
  proj = angr.Project('oldschool')

  # calculate a base offset based on ghidra base
  ghidra_min_addr = 0x10000
  base = proj.loader.min_addr - ghidra_min_addr

  # code addresses
  check_pass_func_addr = base+0x1212a
  before_pass_mixing_addr = base+0x12747
  password_was_good_addr = base+0x129a8

  # global data addresses
  xor_array_addr = base+0x350e0
  feistel_key_triplets_addr = base+0x35160

  # use a call state to start at the password verification function
  state = proj.factory.call_state(check_pass_func_addr, username_ptr, password_ptr, prototype='int c(char * u, char * p)', add_options=angr.options.unicorn)

  # do the initialization that happens on a real execution when debugger isn't detected
  for i in range(32):
    state.mem[xor_array_addr + 4 * i].uint32_t = state.mem[xor_array_addr + 4 * i].uint32_t.concrete ^ claripy.BVV(2, 4*8)

    temp0 = state.mem[feistel_key_triplets_addr + 12 * i].uint32_t.concrete
    temp1 = state.mem[feistel_key_triplets_addr + 12 * i + 4].uint32_t.concrete
    state.mem[feistel_key_triplets_addr + 12 * i].uint32_t = temp1
    state.mem[feistel_key_triplets_addr + 12 * i + 4].uint32_t = temp0

  # run the password checking function up until the point the password starts to be mixed in
  simgr = proj.factory.simulation_manager(state)
  simgr.explore(find=before_pass_mixing_addr)
    
  if len(simgr.found) == 0:
    print(f"Not Solved {pair_num}/{total} {user}")
    break
  else:
    state2 = simgr.found[0]

    # replace the password ints with symbols
    symbolic_vars = []
    password_base = state2.regs.ebp - 0x114
    for i in range(25):
      svar = claripy.BVS(f"pw{i}", 4*8)
      state2.add_constraints(claripy.ULT(svar, 0x20))
      state2.mem[password_base + 4 * i].uint32_t = svar
      symbolic_vars.append(svar)

    # find solution were password is good
    simgr2 = proj.factory.simulation_manager(state2)
    simgr2.explore(find=password_was_good_addr)

    if len(simgr2.found) == 0:
      print(f"Not Solved {pair_num}/{total} {user}")
      break
    else:
      state3 = simgr2.found[0]

      # get the password ints
      concrete_vals = []
      for svar in symbolic_vars:
        val = state3.solver.eval(svar, cast_to=bytes)
        concrete_vals.append(val)

      # convert the password ints back to string using lookup table
      def chunks(l, n):
        for i in range(0, len(l), n):
          yield l[i:i+n]
      lookup = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'
      c = chunks(''.join([lookup[x[-1]] for x in concrete_vals]), 5)
      solved_pw = '-'.join(c) 

      print(f"Solved {pair_num}/{total} {user} {solved_pw}")

      pairs[index] = (user, solved_pw)

# if we found all the password then generate the flag
if pair_num == total:
  print('CTF{' + hashlib.sha1(b'|'.join(f'{u}:{p}'.encode('utf-8') for u, p in pairs)).hexdigest() + '}')
```

Nesse código, feito por [deadmoo83](https://gist.github.com/deadmoo83/fc7a82a7e0b06d8ca45acab9e3cd90c2), em vez de inverter manualmente a matemática do algoritmo (S-box, Feistel, produto de matrizes), foi utilizada a execução simbólica com `angr` para automatizar a geração das senhas.

O script carrega o binário, localiza a função de verificação e, como pula a inicialização normal do programa, desfaz manualmente a ofuscação das tabelas usadas no algoritmo (um XOR fixo e uma troca de valores) que normalmente aconteceria nessa etapa.

Em seguida, executa simbolicamente a função de verificação com o username real e uma senha de formato válido, substituindo os 25 caracteres da senha por variáveis simbólicas. O `angr` usa o Z3 para encontrar os valores que fazem a verificação ter sucesso, sem precisarmos programar a inversão do algoritmo manualmente.

Os valores encontrados são convertidos de volta em caracteres pelo alfabeto da chave, reconstruindo a senha de cada usuário. Com as 50 senhas resolvidas, concatenamos os pares usuário:senha e calculamos o SHA1 da string para obter a flag.

Por conta da execução simbólica, o resultado da flag pode ser demorado.
