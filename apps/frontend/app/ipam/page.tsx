import type { Metadata } from "next";

import { ModulePage } from "@/src/components/module-page";

export const metadata: Metadata = { title: "IPAM" };

export default function IpamPage() {
  return (
    <ModulePage
      capability="Endereçamento por site e routing domain"
      dependency="backend"
      description="Administre IPv4 e IPv6 preservando sobreposição legítima entre domínios de roteamento distintos."
      eyebrow="Address management"
      icon="ipam"
      title="IPAM"
    />
  );
}
