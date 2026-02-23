"use client";

import * as React from "react";
import {
  IconKey,
  IconCpu,
  IconShieldBolt,
  IconRadar,
  IconFileAnalytics,
  IconListSearch,
  IconCommand,
} from "@tabler/icons-react";

import { ArrowUpRight } from "lucide-react";

import { NavMain } from "@/components/layout/base/nav-menu";
import { NavSecondary } from "@/components/layout/base/nav-secondary";
import { NavUser } from "@/components/layout/base/nav-user";

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import Image from "next/image";
import Link from "next/link";

const Lib = () => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
    >
      <path
        d="M16.6127 16.0847C13.9796 17.5678 12.4773 20.641 12 21.5001V8.00005C12.4145 7.25401 13.602 5.11651 15.6317 3.66373C16.4868 3.05172 16.9143 2.74571 17.4572 3.02473C18 3.30376 18 3.91968 18 5.15151V13.9915C18 14.6569 18 14.9896 17.8634 15.2234C17.7267 15.4572 17.3554 15.6664 16.6127 16.0847Z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      ></path>
      <path
        d="M12 7.80556C11.3131 7.08403 9.32175 5.3704 5.98056 4.76958C4.2879 4.4652 3.44157 4.31301 2.72078 4.89633C2 5.47965 2 6.42688 2 8.32133V15.1297C2 16.8619 2 17.728 2.4626 18.2687C2.9252 18.8095 3.94365 18.9926 5.98056 19.3589C7.79633 19.6854 9.21344 20.2057 10.2392 20.7285C11.2484 21.2428 11.753 21.5 12 21.5C12.247 21.5 12.7516 21.2428 13.7608 20.7285C14.7866 20.2057 16.2037 19.6854 18.0194 19.3589C20.0564 18.9926 21.0748 18.8095 21.5374 18.2687C22 17.728 22 16.8619 22 15.1297V8.32133C22 6.42688 22 5.47965 21.2792 4.89633C20.5584 4.31301 19 4.76958 18 5.5"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      ></path>
    </svg>
  );
};

const navConfiguration = [
  {
    title: "API Credentials",
    url: "/credentials",
    icon: IconKey,
  },
  {
    title: "Model Registry",
    url: "/models",
    icon: IconCpu,
  },
];

const navSecurity = [
  {
    title: "Garak Scanner",
    url: "/scanner",
    icon: IconRadar,
  },
  // {
  //   title: "LLM Guard",
  //   url: "/guard",
  //   icon: IconShieldBolt,
  // },
  // {
  //   title: "Scan Reports",
  //   url: "/reports",
  //   icon: IconFileAnalytics,
  // },
  {
    title: "Activity Logs",
    url: "/logs",
    icon: IconListSearch,
  },
];

const navSecondary = [
  {
    title: "cmd/ctrl + k",
    url: "#",
    icon: IconCommand,
  },
  {
    title: "Documentation",
    url: "#",
    icon: Lib,
    secicon: ArrowUpRight,
  },
];

interface UserProp {
  name: string;
  email: string;
  avatar: string;
}

interface AppSidebarProps extends React.ComponentProps<typeof Sidebar> {
  user?: UserProp | null;
}

export function AppSidebar({ user, ...props }: AppSidebarProps) {
  const displayUser = user || {
    name: "Guest",
    email: "guest@example.com",
    avatar: "",
  };

  return (
    <Sidebar className="border-none" collapsible="offcanvas" {...props}>
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              asChild
              className="data-[slot=sidebar-menu-button]:!p-1.5"
            >
              <Link href="/">
                <Image
                  src="/official/logo.png"
                  alt="logo"
                  width={24}
                  height={24}
                />
                <span className="text-base font-semibold cooper">
                  Orazen.
                </span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>
      <SidebarContent>
        <NavMain
          configItems={navConfiguration}
          securityItems={navSecurity}
        />
        <NavSecondary items={navSecondary} className="mt-auto" />
      </SidebarContent>
      <SidebarFooter>
        <NavUser user={displayUser} />
      </SidebarFooter>
    </Sidebar>
  );
}
