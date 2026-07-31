import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Mini SIEM",
  description: "Self-hosted SIEM: ingest, detect, alert.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="font-mono">{children}</body>
    </html>
  );
}
