# Seven Network Manager

Plataforma de gerenciamento de infraestrutura de rede criada e mantida por **Gabriell211**.

O Seven Network Manager centraliza inventário, discovery, IPAM, telemetria, operações de rede e administração de infraestrutura sem exigir que o operador trabalhe diretamente com comandos de baixo nível no fluxo cotidiano.

## Arquitetura

O projeto adota um control plane modular e um runtime local separado para operações que dependem de alcance à LAN/L2.

```text
Browser
  |
  v
apps/frontend
  |
  v
apps/backend (control plane)
  |
  | contrato versionado e autenticado
  v
apps/site-runtime
  |
  v
crates/executor-core
  |
  v
Providers / Transports / Rede gerenciada
```

### Regras estruturais

- `apps/backend` concentra API, autorização, orchestration, estado transacional e decisões de produto.
- `apps/site-runtime` executa operações que precisam alcançar a rede gerenciada e funciona sem sessão gráfica.
- `crates/executor-core` contém o núcleo reutilizável de execução de capabilities, providers e transports.
- `apps/frontend` é a interface web e nunca executa operações de rede diretamente.
- PostgreSQL é a fonte transacional de verdade.
- Redis é usado apenas para estado efêmero, locks, rate limiting e cache compatível com a semântica do domínio.
- Operações são escopadas por `organization`, `site` e `routing_domain`.
- Endereço IP não é identidade global de dispositivo.
- Mudanças administrativas devem ser auditáveis, idempotentes quando aplicável e explicitamente autorizadas.

## Estrutura do monorepo

```text
apps/
  backend/          API/control plane Rust
  frontend/         interface Next.js
  site-runtime/     runtime local Rust headless
crates/
  domain/           tipos e invariantes de domínio
  executor-core/    execução de capabilities/providers/transports
docs/
  adr/              decisões arquiteturais
  architecture.md   visão estrutural
  roadmap.yaml      roadmap validável
  toolchain.yaml    matriz oficial de ferramentas
docker/             imagens e arquivos auxiliares
migrations/         migrations PostgreSQL
packages/
  ui/               componentes compartilhados do frontend
scripts/            validações e automações do repositório
```

## Ciclos de execução

O desenvolvimento segue a ordem de dependências definida nas issues:

- **C0** — arquitetura, modelo de dados e contratos-base.
- **C1** — plataforma, segurança e runtime de execução.
- **C2** — inventário, IPAM e discovery.
- **C3** — SNMP, telemetria e operação observável.
- **C4** — serviços Windows básicos e gate do MVP.
- **C5–C9** — administração ativa, switching, L3, perímetro, automação e gate v1.
- **C10–C13** — multiempresa, sites remotos, HA, telemetria avançada, integrações e gate v2.

O código não deve antecipar dependências posteriores apenas para acelerar uma tela. Cada capability precisa respeitar placement, segurança, contratos e critérios de aceite do seu ciclo.

## Desenvolvimento

### Requisitos oficiais

Consulte `docs/toolchain.yaml`. O baseline do frontend usa Node.js 24 LTS e pnpm 11. O backend e o runtime usam Rust stable pinado pelo repositório.

### Subir infraestrutura local

```bash
cp .env.example .env
docker compose up -d postgres redis
```

### Backend

```bash
cargo run -p snm-backend
```

### Runtime local

```bash
cargo run -p snm-site-runtime
```

### Frontend

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm --filter @seven-network-manager/frontend dev
```

## Segurança por padrão

- Nenhum segredo deve ser enviado ao frontend.
- Nenhum segredo deve ser persistido em texto puro.
- Runtime local não expõe superfície administrativa para a LAN por padrão.
- Operações remotas retornam estados tipados; perda de conectividade nunca vira sucesso presumido.
- `unknown`, `partial`, `cancelled`, `unsupported` e `not_applicable` são estados válidos quando representam a realidade.
- Shell arbitrário não faz parte do contrato público de execução.
- Logs e auditoria precisam preservar correlação sem registrar credenciais.

## Ownership

Owner do roadmap e das entregas: **Gabriell211**.
