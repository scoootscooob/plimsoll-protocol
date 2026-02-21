import { Header } from "@/components/Header";
import { VaultDashboard } from "@/components/VaultDashboard";

export default function Home() {
  return (
    <main className="min-h-screen">
      <Header />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <VaultDashboard />
      </div>
    </main>
  );
}
