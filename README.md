# 🔍 Subscanner — Subdomain Port Scanner

Ferramenta para varredura de portas em listas de subdomínios, com suporte a scan primário e fallback automático via **nmap**.

> **⚠️ Use somente em domínios que você possui ou tem autorização explícita para testar.**
> Varredura não autorizada é ilegal em praticamente todos os países.

---

## O que faz

- Lê uma lista de subdomínios de um arquivo `.txt`
- Executa scan completo de portas TCP via nmap (`-p-`)
- Fallback automático com detecção de serviço (`-sS -Pn -sV`) se o scan primário falhar
- Salva os resultados em arquivos separados por subdomínio
- Filtra e destaca portas de uma lista de portas permitidas (`ALLOWED_PORTS`)
- Valida hostnames antes de escanear para evitar argumentos maliciosos

---

## Requisitos

- Python 3.10+
- nmap instalado no sistema

```bash
# Ubuntu/Debian
sudo apt install nmap

# Arch Linux
sudo pacman -S nmap

# Windows
# Baixe em https://nmap.org/download.html
```

Sem dependências externas de Python além da stdlib.

---

## Instalação

```bash
git clone https://github.com/seu-usuario/subscanner
cd subscanner
```

---

## Uso

```bash
python scan_subdomains.py <arquivo_subdomains> [pasta_saida]
```

### Exemplos

```bash
# Scan básico com saída na pasta padrão (nmap_results/)
python scan_subdomains.py subdomains.txt

# Scan com pasta de saída personalizada
python scan_subdomains.py subdomains.txt resultados/
```

### Formato do arquivo de subdomínios

Um subdomínio por linha, linhas vazias são ignoradas:

```
sub1.exemplo.com
sub2.exemplo.com
mail.exemplo.com
```

---

## Saída

Os resultados são salvos em arquivos `.txt` na pasta de saída, um por subdomínio, com o label do scan usado (`primary` ou `fallback`):

```
nmap_results/
  sub1.exemplo.com_primary_scan.txt
  sub2.exemplo.com_fallback_scan.txt
```

No terminal, o programa exibe todas as portas abertas encontradas e destaca as que estão na lista `ALLOWED_PORTS`.

---

## Configuração

Edite a variável `ALLOWED_PORTS` no topo do script para ajustar quais portas são destacadas:

```python
ALLOWED_PORTS = {
    9050, 9150, 1080, 8080, 3128, 8081, 8888, 9999,
    *range(1081, 1251)
}
```

O timeout padrão por scan é de **300 segundos** — ajuste `SCAN_TIMEOUT` conforme necessário.

---

## Casos de uso legítimos

- Bug bounty (dentro do escopo definido pelo programa)
- Pentest com contrato assinado
- Reconhecimento em infraestrutura própria
- CTFs e ambientes de laboratório

---

## Licença

MIT — veja `LICENSE`.
