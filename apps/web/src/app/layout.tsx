import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MaintenX — Enterprise Facility Maintenance SaaS",
  description: "Next-generation facility maintenance, asset lifecycle, and work order management platform.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased selection:bg-sky-500 selection:text-white">
        {children}
      </body>
    </html>
  );
}
