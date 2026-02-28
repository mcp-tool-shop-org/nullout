<p align="center">
  <a href="README.ja.md">日本語</a> | <a href="README.zh.md">中文</a> | <a href="README.es.md">Español</a> | <a href="README.fr.md">Français</a> | <a href="README.hi.md">हिन्दी</a> | <a href="README.it.md">Italiano</a> | <a href="README.md">English</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/mcp-tool-shop-org/brand/main/logos/nullout/readme.png" width="400" alt="NullOut">
</p>

<p align="center">
  <a href="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml"><img src="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/mcp-tool-shop-org/nullout"><img src="https://codecov.io/gh/mcp-tool-shop-org/nullout/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/mcp-tool-shop-org/nullout/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"></a>
  <a href="https://mcp-tool-shop-org.github.io/nullout/"><img src="https://img.shields.io/badge/Landing_Page-live-blue" alt="Landing Page"></a>
</p>

Servidor MCP que encontra e remove com segurança arquivos "indeléveis" no Windows.

O Windows reserva nomes de dispositivos como `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9` e `LPT1`-`LPT9` na camada Win32. Arquivos com esses nomes podem existir no NTFS (criados via WSL, ferramentas Linux ou APIs de baixo nível), mas se tornam impossíveis de renomear, mover ou excluir através do Explorador ou comandos do shell.

O NullOut procura por essas entradas perigosas e as remove com segurança usando o namespace de caminho estendido `\\?\`, com um fluxo de trabalho de confirmação em duas etapas projetado para hosts MCP.

## Como funciona

1. **Verifica** um diretório especificado em busca de conflitos de nomes reservados, pontos/espaços extras e caminhos muito longos.
2. **Planeja** a limpeza — o NullOut gera um token de confirmação para cada entrada, vinculado à identidade do arquivo (número de série do volume + ID do arquivo).
3. **Exclui** com o token — o NullOut verifica novamente se o arquivo não foi alterado (proteção TOCTOU) antes de removê-lo usando o namespace estendido.

## Modelo de segurança

- **Apenas raízes especificadas** — as operações são restritas a diretórios que você configura explicitamente.
- **Nenhum caminho bruto em chamadas destrutivas** — a exclusão aceita apenas IDs de descoberta emitidos pelo servidor + tokens de confirmação.
- **Política de negação total para pontos de análise** — junções, links simbólicos e pontos de montagem nunca são acessados ou excluídos.
- **Vinculação da identidade do arquivo** — os tokens são assinados com HMAC e vinculados ao número de série do volume + ID do arquivo; qualquer alteração entre a verificação e a exclusão é rejeitada.
- **Apenas diretórios vazios** — a versão 1 se recusa a excluir diretórios não vazios.
- **Erros estruturados** — cada falha retorna um código legível por máquina com sugestões para o próximo passo.

## Ferramentas MCP

| Ferramenta | Tipo | Propósito |
|------|------|---------|
| `list_allowed_roots` | somente leitura | Exibe as raízes de verificação configuradas. |
| `scan_reserved_names` | somente leitura | Encontra entradas perigosas em uma raiz. |
| `get_finding` | somente leitura | Obtém detalhes completos sobre uma descoberta. |
| `plan_cleanup` | somente leitura | Gera um plano de exclusão com tokens de confirmação. |
| `delete_entry` | destrutiva | Exclui um arquivo ou diretório vazio (requer token). |
| `who_is_using` | somente leitura | Identifica processos que estão bloqueando um arquivo (Gerenciador de Reinicialização). |
| `get_server_info` | somente leitura | Metadados do servidor, políticas e capacidades. |

## Configuração

Defina as raízes permitidas por meio de uma variável de ambiente:

```
NULLOUT_ROOTS=C:\Users\me\Downloads;C:\temp\cleanup
```

Segredo de assinatura do token (gere um valor aleatório):

```
NULLOUT_TOKEN_SECRET=your-random-secret-here
```

## Modelo de ameaças

O NullOut se protege contra:

- **Uso destrutivo** — a exclusão requer um token de confirmação emitido pelo servidor; nenhum caminho bruto é aceito.
- **Travessia de caminho** — todas as operações são restritas a raízes permitidas; escapes ".." são resolvidos e rejeitados.
- **Escapes de pontos de análise** — junções, links simbólicos e pontos de montagem nunca são acessados ou excluídos (negação total).
- **Corridas TOCTOU** — os tokens são vinculados com HMAC ao número de série do volume + ID do arquivo; qualquer alteração na identidade entre a verificação e a exclusão é rejeitada.
- **Truques de namespace** — as operações destrutivas usam o prefixo de caminho estendido `\\?\` para contornar a análise de nome Win32.
- **Arquivos bloqueados** — a atribuição do Gerenciador de Reinicialização é somente leitura; o NullOut nunca encerra processos.
- **Diretórios não vazios** — recusados por política; apenas diretórios vazios podem ser excluídos.

**Dados acessados:** metadados do sistema de arquivos (nomes, IDs de arquivos, números de série de volumes), metadados do processo (PIDs, nomes de aplicativos via Gerenciador de Reinicialização).
**Dados NÃO acessados:** conteúdo de arquivos, rede, credenciais, registro do Windows.
**Nenhuma telemetria** é coletada ou enviada.

## Requisitos

- Windows 10/11
- Python 3.10+

---

Criado por <a href="https://mcp-tool-shop.github.io/">MCP Tool Shop</a
