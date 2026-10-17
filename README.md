# Linkshield 🛡️

Um validador de links desenvolvido em Python para identificar sinais que podem indicar URLs suspeitas.

## Funcionalidades

- Análise da estrutura de URLs.
- Verificação do uso de HTTPS.
- Identificação de URLs que utilizam endereços IP.
- Detecção de caracteres Unicode visualmente semelhantes a letras latinas.
- Comparação de domínios com uma lista de serviços conhecidos.
- Estimativa de risco com base nos sinais identificados.
- Integração opcional com o Google Safe Browsing.

## Tecnologias utilizadas

- Python
- Git e GitHub
- Google Safe Browsing API (opcional)

## Como executar

1. Instale o Python.
2. Clone ou baixe este repositório.
3. Abra o terminal na pasta do projeto.
4. Execute:

```bash
python main.py
```

Digite uma URL quando solicitado. Para encerrar o programa, pressione `Enter` sem informar um link.

## Google Safe Browsing (opcional)

O projeto pode consultar o Google Safe Browsing usando uma chave de API armazenada na variável de ambiente `SAFE_BROWSING_API_KEY`.

No PowerShell, configure a variável para a sessão atual:

```powershell
$env:SAFE_BROWSING_API_KEY = "SUA_CHAVE_AQUI"
python main.py
```

**Importante:** nunca publique sua chave de API no repositório.

Quando essa variável não estiver configurada, o programa executa apenas as verificações locais.

## Limitações

O Linkshield é um projeto de estudo e não garante que um link seja seguro ou malicioso. A análise local utiliza heurísticas, que podem gerar falsos positivos ou deixar de identificar ameaças.

Quando o Google Safe Browsing está ativado, a URL consultada é enviada ao serviço para verificação.

## Objetivo

Projeto desenvolvido para praticar Python, manipulação de URLs, funções, estruturas condicionais, tratamento de dados e conceitos introdutórios de segurança da informação.