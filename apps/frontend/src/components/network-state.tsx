"use client";

import { useEffect, useState } from "react";

import { Icon } from "./icon";

export function NetworkState() {
  const [online, setOnline] = useState<boolean | null>(null);

  useEffect(() => {
    const sync = () => setOnline(window.navigator.onLine);
    sync();
    window.addEventListener("online", sync);
    window.addEventListener("offline", sync);
    return () => {
      window.removeEventListener("online", sync);
      window.removeEventListener("offline", sync);
    };
  }, []);

  if (online === null) {
    return <span className="connectivity-chip connectivity-chip--pending">Verificando conexão</span>;
  }

  return (
    <span className={`connectivity-chip ${online ? "connectivity-chip--online" : "connectivity-chip--offline"}`}>
      <Icon name={online ? "network" : "offline"} size={16} />
      {online ? "Cliente online" : "Cliente offline"}
    </span>
  );
}
