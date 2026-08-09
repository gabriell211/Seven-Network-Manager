import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Seven Network Manager",
  description: "Control plane for network infrastructure management",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="pt-BR">
      <body>{children}</body>
    </html>
  );
}
