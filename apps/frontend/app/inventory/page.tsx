import type { Metadata } from "next";

import { ModulePage } from "@/src/components/module-page";

export const metadata: Metadata = { title: "Inventário" };

export default function InventoryPage() {
  return (
    <ModulePage
      capability="Inventário com identidade e lifecycle explícitos"
      dependency="backend"
      description="Gerencie ativos e sua identidade técnica sem usar endereço IP como identidade global."
      eyebrow="Ativos gerenciados"
      icon="inventory"
      title="Inventário"
    />
  );
}
