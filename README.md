# Seven Network Manager

Plataforma de gerenciamento de infraestrutura de rede criada e mantida por **Gabriell211**.

O Seven Network Manager (SNM) centraliza inventário, IPAM, discovery, telemetria e operações administrativas sem transformar o navegador em executor privilegiado e sem espalhar comandos de fabricante pela regra de negócio.

> Estado atual deste branch: fundação executável de C0 + início da boundary de C1. O roadmap completo continua nas issues #1–#118; funcionalidades futuras não são anunciadas como prontas antes dos respectivos critérios de aceite.

## Arquitetura

```text
Browser
  |
  v
apps/frontend                  Next.js / interface
  |
  v
apps/backend                   Rust/Axum / control plane
  |
  | contrato local versionável
  v
apps/site-runtime              Rust / processo headless
  |
  v
crates/executor-core           execução técnica reutilizável
  |
  v
Providers / Transports / Rede gerenciada
```

### Regras estruturais

- `apps/backend` concentra API, orchestration, política e estado transacional.
- `apps/site-runtime` é processo independente e executa operações que precisam alcançar a LAN.
- `crates/executor-core` não depende de Axum, Next.js, Tauri, banco ou handlers do control plane.
- `apps/frontend` nunca executa probe/transport diretamente.
- PostgreSQL é a fonte transacional de verdade.
- Redis é efêmero: cache/coordenação, não segunda fonte autoritativa.
- MongoDB é profile opcional sem dataset autoritativo por padrão.
- RabbitMQ só entra quando distribuição/HA justificar; não é requisito do MVP local.
- Operações L3 carregam `organization + site + routing-domain`.
- IP não é identidade global de dispositivo.
- IPv6 link-local exige escopo de interface.
- Runtime indisponível gera estado explícito; o backend não contorna a boundary executando direto na LAN.

Leia [docs/architecture.md](docs/architecture.md) e os ADRs em [docs/adr](docs/adr).

## Estrutura

```text
apps/
  backend/            API/control plane Rust
  frontend/           painel Next.js self-hostable
  site-runtime/       runtime local Rust headless
crates/
  domain/             IDs, invariantes e contratos de domínio puros
  executor-core/      execução técnica sem UI/control-plane/database
deploy/
  systemd/            unidade de serviço do runtime
docs/
  adr/                decisões arquiteturais
  architecture.md     arquitetura e boundaries
  api-contract.md     baseline do contrato HTTP
  toolchain.yaml      matriz/pins de toolchain
migrations/
  0001_foundation.sql schema PostgreSQL inicial
scripts/
  validate_repo.py    lint estrutural/arquitetural
docker-compose.yml    datastores locais e profiles opcionais
```

## Toolchain

A fonte versionada é `docs/toolchain.yaml`.

- Node: 24 LTS, patch pinado em `.node-version`.
- pnpm: 11.x, patch pinado em `packageManager`.
- Rust: stable pinado por `rust-toolchain.toml`.
- Frontend usa Next.js/React/TypeScript/Tailwind em versões exatas aprovadas pelo manifesto.

### Observação sobre Next.js 16.3

O roadmap original registra `16.3.x`. Na revisão de 2026-08-09, a documentação oficial ainda apresentava 16.3 como Preview e 16.2.11 como Active LTS corrigida. Este bootstrap prioriza a linha estável e registra a exceção em `docs/toolchain.yaml`; o projeto não promove prerelease para “cumprir número” de roadmap.

## Configuração local

```bash
cp .env.example .env
```

Troque obrigatoriamente `POSTGRES_PASSWORD` e `SNM_RUNTIME_TOKEN` antes de subir os serviços. O token do runtime deve possuir pelo menos 32 caracteres e não pode manter o valor demonstrativo.

## Datastores

```bash
docker compose up -d postgres redis
```

Profiles opcionais:

```bash
docker compose --profile mongo up -d mongo
docker compose --profile distributed up -d rabbitmq
```

As portas de desenvolvimento são publicadas apenas em `127.0.0.1`. `privileged: true` não faz parte do baseline.

## Backend

```bash
cargo run -p snm-backend
```

Endpoints iniciais:

- `GET /health`
- `GET /ready`
- `GET /api/v1/system`

`/ready` relata a disponibilidade do runtime separadamente. Um runtime offline deixa o control plane degradado/observável; não habilita fallback de execução direta.

## Runtime local

```bash
SNM_RUNTIME_TOKEN='use-um-segredo-com-32-ou-mais-caracteres' \
  cargo run -p snm-site-runtime
```

Superfície local:

- `GET /health`
- `GET /ready`
- `GET /v1/capabilities` — autenticado
- `POST /v1/execute/tcp-connect` — autenticado

Por padrão o runtime:

- escuta somente `127.0.0.1:9765`;
- recusa bind não-loopback sem opt-in explícito;
- recusa token default/fraco;
- bloqueia destinos públicos no probe TCP;
- aceita somente target consistente com organization/site/routing-domain do envelope;
- não acessa PostgreSQL/Redis;
- não depende de janela, tray, WebView ou Tauri.

A capability `network.tcp.connect` existe como primeiro contract test vertical da boundary e não substitui a implementação completa de discovery/checks das issues posteriores.

### systemd

`deploy/systemd/snm-site-runtime.service` demonstra o lifecycle headless com hardening básico. Em produção, o serviço deve usar usuário dedicado e `/etc/seven-network-manager/runtime.env` com permissões restritas.

## Modelo PostgreSQL

`migrations/0001_foundation.sql` inicia:

- organizations/sites;
- users/service accounts/sessions;
- roles/permissions/bindings;
- devices/identifiers/interfaces;
- routing domains;
- IPv4/IPv6 prefixes e addresses com tipos `cidr`/`inet`;
- credential profile metadata sem secret em claro;
- jobs/job steps;
- alerts/events/maintenance;
- audit append-only;
- transactional outbox-ready;
- system settings.

O schema permite que duas VRFs do mesmo site usem `10.0.0.1` sem colisão indevida e exige interface para IPv6 link-local.

## Frontend

```bash
corepack enable
corepack prepare pnpm@11.21.0 --activate
pnpm install --frozen-lockfile
pnpm --filter @seven-network-manager/frontend dev
```

O shell inicial mostra o estado do control plane e já usa Valibot na fronteira de configuração externa. O DTO do `/api/v1/system` ainda está marcado como temporário; #8 substituirá a interface manual por tipos gerados de OpenAPI.

## Quality gates

```bash
python3 scripts/validate_repo.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
pnpm install --frozen-lockfile
pnpm --filter @seven-network-manager/frontend typecheck
pnpm --filter @seven-network-manager/frontend lint
pnpm --filter @seven-network-manager/frontend build
```

`validate_repo.py` bloqueia, entre outros:

- lockfiles concorrentes Node;
- `privileged: true`;
- imagem Docker `latest`;
- dependência indevida de UI/Axum/database no executor core;
- marcadores de execução direta no backend;
- drift básico de Node/pnpm/React;
- ausência dos invariantes de routing-domain/INET/CIDR/audit/outbox na migration.

## Segurança por padrão

- Nenhum segredo deve ser enviado ao frontend.
- Nenhum segredo operacional deve ser persistido em texto puro.
- Runtime local não expõe superfície administrativa para a LAN por default.
- Payload do runtime é tratado como entrada não confiável.
- Operações remotas retornam estados tipados; perda de confirmação não vira sucesso presumido.
- Shell arbitrário não faz parte do contrato público.
- Logs/audit preservam correlação sem registrar credenciais.
- Mudanças administrativas futuras precisam de RBAC, auditoria, idempotência/concorrência e change-control conforme risco.

## Roadmap

A ordem de implementação não é o número da issue. Os ciclos oficiais são:

- **C0** arquitetura, modelo de dados e contratos-base;
- **C1** plataforma, segurança e runtime;
- **C2** inventário/IPAM/discovery;
- **C3** SNMP/telemetria/operação observável;
- **C4** Windows/DHCP/DNS + gate MVP;
- **C5–C9** administração ativa, L2/L3, automação + gate v1;
- **C10–C13** multiempresa, sites remotos, HA, telemetria avançada, integrações e gate v2.

A execução deve seguir `hardDependencies`; scaffolding não é motivo para encerrar issue funcional sem testes/aceite.

## Ownership

Owner do roadmap e das entregas: **Gabriell211**.
