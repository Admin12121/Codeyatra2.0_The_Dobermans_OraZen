"use client";

import { IconCirclePlusFilled, type Icon } from "@tabler/icons-react";
import Link from "next/link";
import { usePathname } from "next/navigation";

import {
  SidebarGroup,
  SidebarGroupLabel,
  SidebarGroupContent,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";

type NavItem = {
  title: string;
  url: string;
  icon?: Icon;
};

export function NavMain({
  configItems,
  securityItems,
}: {
  configItems: NavItem[];
  securityItems: NavItem[];
}) {
  const pathname = usePathname();

  return (
    <SidebarGroup>
      <SidebarGroupContent className="flex flex-col gap-2 mt-5">
        <SidebarMenu>
          <SidebarMenuItem className="flex items-center gap-2">
            <SidebarMenuButton
              asChild
              tooltip="Dashboard"
              isActive={pathname === "/dashboard"}
              className="bg-primary text-primary-foreground hover:bg-primary/90 hover:text-primary-foreground active:bg-primary/90 active:text-primary-foreground min-w-8 duration-200 ease-linear"
            >
              <Link href="/dashboard">
                <IconCirclePlusFilled />
                <span>Dashboard</span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>

        <SidebarGroupLabel>
          <div className="mt-5 flex items-center gap-3.5 pl-2 pb-2">
            <div className="w-4.5 h-0.5 rounded-xs bg-red-600"></div>
            <p className="text-stone-400 font-medium text-xs uppercase font-mono grow">
              Configuration
            </p>
          </div>
        </SidebarGroupLabel>
        <SidebarMenu className="gap-2">
          {configItems.map((item) => (
            <SidebarMenuItem key={item.title}>
              <SidebarMenuButton
                asChild
                tooltip={item.title}
                isActive={pathname === item.url}
              >
                <Link href={item.url}>
                  {item.icon && <item.icon />}
                  <span>{item.title}</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>

        <SidebarGroupLabel>
          <div className="mt-5 flex items-center gap-3.5 pl-2 pb-2">
            <div className="w-4.5 h-0.5 rounded-xs bg-amber-400"></div>
            <p className="text-stone-400 font-medium text-xs uppercase font-mono grow">
              Security Suite
            </p>
          </div>
        </SidebarGroupLabel>
        <SidebarMenu className="gap-2">
          {securityItems.map((item) => (
            <SidebarMenuItem key={item.title}>
              <SidebarMenuButton
                asChild
                tooltip={item.title}
                isActive={pathname === item.url}
              >
                <Link href={item.url}>
                  {item.icon && <item.icon />}
                  <span>{item.title}</span>
                </Link>
              </SidebarMenuButton>
            </SidebarMenuItem>
          ))}
        </SidebarMenu>
      </SidebarGroupContent>
    </SidebarGroup>
  );
}
