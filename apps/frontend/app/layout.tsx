import type { Metadata, Viewport } from "next";

import { ProductShell } from "@/src/components/product-shell";
import { getPlatformSnapshot } from "@/src/lib/api";

import "./globals.css";
import "./operational.css";

export const metadata: Metadata = {
  title: {
    default: "Seven Network Manager",
    template: "%s · Seven Network Manager",
  },
  description: "Control plane on-premises para gerenciamento seguro de infraestrutura de rede.",
  applicationName: "Seven Network Manager",
  manifest: "/manifest.webmanifest",
  icons: {
    icon: [{ url: "/icon.svg", type: "image/svg+xml" }],
    shortcut: ["/icon.svg"],
    apple: [{ url: "/icon.svg", type: "image/svg+xml" }],
  },
};

export const viewport: Viewport = {
  colorScheme: "dark light",
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#070b12" },
    { media: "(prefers-color-scheme: light)", color: "#f5f7fb" },
  ],
};

export default async function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  const snapshot = await getPlatformSnapshot();

  return (
    <html lang="pt-BR">
      <body>
        <ProductShell snapshot={snapshot}>{children}</ProductShell>
      </body>
    </html>
  );
}
