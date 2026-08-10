import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Seven Network Manager",
    short_name: "Seven NM",
    description: "Control plane on-premises para gerenciamento seguro de infraestrutura de rede.",
    start_url: "/",
    display: "standalone",
    background_color: "#070b12",
    theme_color: "#07111f",
    icons: [
      {
        src: "/icon.svg",
        sizes: "any",
        type: "image/svg+xml",
        purpose: "any",
      },
    ],
  };
}
