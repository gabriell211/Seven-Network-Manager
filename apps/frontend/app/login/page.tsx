import { Brand } from "@/src/components/brand";
import { Icon } from "@/src/components/icon";
import { LoginForm } from "@/src/components/login-form";

export default function LoginPage() {
  return (
    <div className="login-page">
      <section className="login-card" aria-labelledby="login-title">
        <div className="login-card__brand"><Brand /></div>
        <div className="login-card__copy">
          <span className="eyebrow">Acesso administrativo</span>
          <h1 id="login-title">Entre no Seven Network Manager</h1>
          <p>Autenticação do control plane. Credenciais de dispositivos nunca são solicitadas nesta tela.</p>
        </div>
        <LoginForm />
        <div className="login-card__security">
          <Icon name="shield" size={18} />
          <span>Sessão protegida por cookie HttpOnly, SameSite e validação server-side.</span>
        </div>
      </section>

      <aside className="login-context" aria-label="Boundary de execução">
        <span className="login-context__icon"><Icon name="runtime" size={28} /></span>
        <span className="eyebrow">Execution boundary</span>
        <h2>O navegador administra. O runtime executa.</h2>
        <p>Operações na LAN continuam isoladas no site-runtime headless; a interface não abre sockets de rede nem acessa segredos operacionais.</p>
      </aside>
    </div>
  );
}
