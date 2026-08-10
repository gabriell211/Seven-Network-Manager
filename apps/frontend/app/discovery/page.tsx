import type { Metadata } from "next";

import { ModulePage } from "@/src/components/module-page";

export const metadata: Metadata = { title: "Discovery" };

export default function DiscoveryPage() {
  return (
    <ModulePage
      capability="Descoberta executada exclusivamente no site-runtime"
      dependency="runtime"
      description="Descubra a rede gerenciada sem transferir privilégios LAN para o navegador ou para o control plane."
      eyebrow="Descoberta de rede"
      icon="discovery"
      title="Discovery"
    />
  );
}
