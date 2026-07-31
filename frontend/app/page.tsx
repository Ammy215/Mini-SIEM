async function getBackendStatus(): Promise<string> {
  try {
    const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/health`, {
      cache: "no-store",
    });
    const data = await res.json();
    return data.status ?? "unknown";
  } catch {
    return "unreachable";
  }
}

export default async function Home() {
  const status = await getBackendStatus();

  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-4 p-24">
      <h1 className="text-2xl">Mini SIEM</h1>
      <p className="text-sm text-slate-400">backend status: {status}</p>
    </main>
  );
}
