import "./styles.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "Seven Network Manager",
  description: "On-premise network management control plane.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="pt-BR">
      <body>{children}</body>
    </html>
  );
}
