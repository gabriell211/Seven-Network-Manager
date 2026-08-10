"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

import { OperationalIcon } from "./operational-icon";

export function LogoutButton() {
  const router = useRouter();
  const [pending, setPending] = useState(false);

  async function logout() {
    setPending(true);
    try {
      await fetch("/api/session/logout", { method: "POST" });
    } finally {
      router.replace("/login");
      router.refresh();
      setPending(false);
    }
  }

  return (
    <button className="icon-action" disabled={pending} onClick={logout} title="Encerrar sessão" type="button">
      <OperationalIcon name="logout" size={17} />
      <span>{pending ? "Saindo…" : "Sair"}</span>
    </button>
  );
}
