Nesse código, em vez de inverter manualmente a matemática do algoritmo (S-box, Feistel, produto de matrizes), foi utilizada a execução simbólica com `angr` para automatizar a geração das senhas.

O script carrega o binário, localiza a função de verificação e, como pula a inicialização normal do programa, desfaz manualmente a ofuscação das tabelas usadas no algoritmo (um XOR fixo e uma troca de valores) que normalmente aconteceria nessa etapa.

Em seguida, executa simbolicamente a função de verificação com o username real e uma senha de formato válido, substituindo os 25 caracteres da senha por variáveis simbólicas. O `angr` usa o Z3 para encontrar os valores que fazem a verificação ter sucesso, sem precisarmos programar a inversão do algoritmo manualmente.

Os valores encontrados são convertidos de volta em caracteres pelo alfabeto da chave, reconstruindo a senha de cada usuário. Com as 50 senhas resolvidas, concatenamos os pares usuário:senha e calculamos o SHA1 da string para obter a flag.

Por conta da execução simbólica, o resultado da flag pode ser demorado.
