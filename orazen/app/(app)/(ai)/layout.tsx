import { AppSidebar } from "@/components/layout/base/app-sidebar";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { getRequiredSession } from "@/lib/session";
import { getOrCreateOrganization } from "@/lib/actions/organization";

export default async function Layout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const session = await getRequiredSession();
  try {
    await getOrCreateOrganization();
  } catch (e) {
    console.error("Failed to initialize organization:", e);
  }

  const user = {
    name: session.user.name || session.user.email.split("@")[0],
    email: session.user.email,
    avatar: session.user.image || "",
  };

  return (
    <main className="container-wrapper section-soft flex-1">
      <SidebarProvider
        style={
          {
            "--sidebar-width": "calc(var(--spacing) * 72)",
            "--header-height": "calc(var(--spacing) * 12)",
          } as React.CSSProperties
        }
      >
        <AppSidebar user={user} />
        <SidebarInset className="overflow-auto max-h-dvh">
          {children}
        </SidebarInset>
      </SidebarProvider>
    </main>
  );
}
