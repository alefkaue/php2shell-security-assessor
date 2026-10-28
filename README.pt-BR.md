# Avaliação defensiva de inventários PHP

**Área do portfólio:** [Cybersecurity](https://github.com/alefkaue#cybersecurity) · **Contexto:** Projeto pessoal

Projeto pessoal de Alef Kaue Santos Nunes, desenvolvido com assistência de IA e testes automatizados.
Lê inventários locais, distingue evidência de suposição e gera relatórios. Não explora RCE nem faz varreduras.

```console
python -m php_assessor --inventory examples/inventory.json --as-of 2026-10-23 --out examples/output
python -m unittest discover -s tests -v
```

Requer Python 3.11+, sem dependências de execução externas. O exemplo é inteiramente sintético.

`affected_version` significa que a versão informada pertence à faixa afetada, não que houve invasão.
`fixed_upstream` se refere somente às duas CVEs estudadas. Pacotes de distribuição antigos podem
ter correções retroportadas: recebem `needs_vendor_review` até existir evidência específica.
Ramos sem suporte continuam sinalizados como `unsupported`. Banners, tags e dados incompletos
ficam `unknown`. Uma referência de correção validada pelo operador é registrada com essa origem explícita.

O coletor local consulta somente o PHP CLI selecionado. FPM, Apache e aplicações embarcadas precisam
de inventário próprio. O parser de configuração não resolve todas as sobreposições de configuração.
Nenhuma diretiva é alterada. Medidas temporárias não substituem atualizar e reiniciar os workers.

Docker: lê exportação de `docker inspect`. SBOM: lê componentes PHP de CycloneDX JSON.
O relatório HTML é estático, sem painel hospedado. Consulte o [modelo de decisão](docs/assessment-model.md)
e a [pesquisa com fontes oficiais](docs/research.md).
