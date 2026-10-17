"""
Validador de links 

Analisa o TEXTO da URL, sem abrir o site, e opcionalmente consulta o
Google Safe Browsing. Nenhuma análise garante que um link é seguro.

Para ativar o Safe Browsing, defina a variável de ambiente com sua chave:
  Windows (PowerShell):  $env:SAFE_BROWSING_API_KEY = "sua_chave"
  Linux / macOS:         export SAFE_BROWSING_API_KEY="sua_chave"
"""
import ipaddress
import json
import os
import unicodedata
import urllib.error
import urllib.request
from urllib.parse import urlsplit

# domínios oficiais usados como referência para detectar possíveis imitações
OFICIAIS = ["google.com", "instagram.com", "facebook.com", "whatsapp.com",
            "paypal.com", "microsoft.com", "netflix.com", "itau.com.br",
            "bradesco.com.br", "nubank.com.br", "santander.com.br",
            "caixa.gov.br", "mercadolivre.com.br"]

# caracteres cirílicos visualmente semelhantes a letras latinas
PARECIDAS = {"\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
             "\u0441": "c", "\u0445": "x", "\u0443": "y", "\u0456": "i"}

API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

def levenshtein(a, b):
    """Quantas edições (inserir, apagar, trocar) separam a de b."""
    anterior = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        atual = [i]
        for j, cb in enumerate(b, 1):
            atual.append(min(anterior[j] + 1, atual[j - 1] + 1,
                             anterior[j - 1] + (ca != cb)))
        anterior = atual
    return anterior[-1]

def nome_principal(host):
    """'www.google.com' -> 'google' | 'x.itau.com.br' -> 'itau'."""
    partes = host.split(".")
    if len(partes) >= 3 and partes[-2] in ("com", "gov", "org", "net"):
        return partes[-3]
    return partes[-2] if len(partes) >= 2 else host

# as verificações locais devolvem uma lista de (pontuação, mensagem)

def checar_estrutura(url, partes, host):
    alertas = []
    if partes.scheme != "https":
        alertas.append((10, "Não usa HTTPS."))
    if "@" in partes.netloc:
        alertas.append((25, "Tem '@' na URL: o navegador ignora o que vem antes dele."))
    try:
        ipaddress.ip_address(host)
        alertas.append((30, "Usa endereço IP em vez de nome de domínio."))
    except ValueError:
        pass
    if len(host.split(".")) > 4:
        alertas.append((10, "Subdomínios demais."))
    return alertas

def checar_unicode(host):
    alertas = []
    estranhos = [c for c in host if ord(c) > 127]
    if estranhos:
        c = estranhos[0]
        alertas.append((15, f"Caracteres fora do ASCII, ex.: {c!r} "
                            f"(U+{ord(c):04X} {unicodedata.name(c, '?')})."))
    for parte in host.split("."):
                # O primeiro termo do nome Unicode indica o alfabeto do caractere.
        alfabetos = {unicodedata.name(c, "?").split()[0] for c in parte if c.isalpha()}
        if len(alfabetos) > 1:
            alertas.append((40, f"Alfabetos misturados em '{parte}': "
                                f"{', '.join(sorted(alfabetos))}."))
    return alertas

def checar_imitacao(host):
        # Substitui alguns caracteres visualmente semelhantes antes da comparação.
    visual = "".join(PARECIDAS.get(c, c) for c in host)
    principal = nome_principal(visual)
    for oficial in OFICIAIS:
        if host == oficial or host.endswith("." + oficial):
            continue
        marca = nome_principal(oficial)
        if nome_principal(host) != marca and principal == marca:
            return [(45, f"Parece '{oficial}', mas com letras trocadas.")]
        if len(marca) >= 5 and levenshtein(principal, marca) == 1:
            return [(35, f"'{principal}' é quase igual a '{marca}' ({oficial}).")]
        if marca in principal and principal != marca:
            return [(25, f"Contém '{marca}', mas não é o site oficial ({oficial}).")]
        if marca in host.split(".")[:-2]:
            return [(35, f"'{marca}' aparece só como subdomínio; o domínio real é outro.")]
    return []

def consultar_safe_browsing(url, chave):
    """Devolve lista de ameaças encontradas ([] = nada) ou None se a consulta falhou."""
    corpo = {
        "client": {"clientId": "validador-estudo", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    req = urllib.request.Request(
        f"{API}?key={chave}", data=json.dumps(corpo).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            dados = json.load(resp)
    except (urllib.error.URLError, ValueError):
        return None
    return [m["threatType"] for m in dados.get("matches", [])]

def analisar(url, chave=None):
    if "://" not in url:
        url = "http://" + url
    partes = urlsplit(url)
    host = (partes.hostname or "").rstrip(".")
    if partes.scheme not in ("http", "https") or not host:
        return None, ["URL inválida."], False

    alertas = (checar_estrutura(url, partes, host)
               + checar_unicode(host)
               + checar_imitacao(host))
    pontos = min(100, sum(p for p, _ in alertas))
    mensagens = [m for _, m in alertas]

    perigoso = False
    if chave:
        ameacas = consultar_safe_browsing(url, chave)
        if ameacas is None:
            mensagens.append("Safe Browsing indisponível (rede, chave ou cota).")
        elif ameacas:
            perigoso = True
            mensagens.append("Google Safe Browsing listou esta URL: " + ", ".join(ameacas))
        else:
            mensagens.append("Safe Browsing: não listada (isso NÃO prova que é segura).")
    return pontos, mensagens, perigoso

def classificar(pontos, perigoso):
    if perigoso:
        return "PERIGOSO"
    if pontos == 0:
        return "Nenhum sinal encontrado"
    return "Atenção" if pontos < 30 else "Suspeito" if pontos < 60 else "Alto risco"

def main():
    chave = os.environ.get("SAFE_BROWSING_API_KEY")
    print("Safe Browsing:", "ATIVO (as URLs são enviadas ao Google)" if chave
          else "desligado (só análise local)")
    while True:
        url = input("\nLink (Enter para sair): ").strip()
        if not url:
            break
        pontos, mensagens, perigoso = analisar(url, chave)
        if pontos is None:
            print(mensagens[0])
            continue
        print(f"Resultado: {classificar(pontos, perigoso)} ({pontos}/100)")
        for m in mensagens:
            print(" -", m)
        print("Lembrete: nenhuma análise automática garante que um link é seguro.")

if __name__ == "__main__":
    main()
