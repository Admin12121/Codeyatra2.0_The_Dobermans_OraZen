"use client";

import {
  IconBolt,
  IconCoin,
  IconLogout,
  IconUserCircle,
  IconLoader2,
  IconRosetteDiscountCheck,
  IconSparkles,
  IconMoon,
  IconSun,
  IconDeviceDesktop,
} from "@tabler/icons-react";

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { ChevronsUpDown } from "lucide-react";
import { signOut } from "@/lib/auth-client";
import { useRouter } from "next/navigation";
import { useState, useEffect } from "react";
import { useSubscription } from "@/hooks/use-subscription";
import { useTheme } from "next-themes";


function ThemeSwitcher() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return (
      <div className="flex items-center justify-between px-2 py-1.5">
        <div className="flex items-center gap-2 text-sm">
          <IconSun size={16} className="text-muted-foreground" />
          <span>Theme</span>
        </div>
        <div className="flex items-center gap-0.5 rounded-lg border border-border bg-muted/50 p-0.5">
          <div className="h-6 w-6" />
          <div className="h-6 w-6" />
          <div className="h-6 w-6" />
        </div>
      </div>
    );
  }

  const options = [
    { value: "dark", icon: IconMoon, label: "Dark" },
    { value: "light", icon: IconSun, label: "Light" },
    { value: "system", icon: IconDeviceDesktop, label: "System" },
  ] as const;

  return (
    <div className="flex items-center justify-between px-2 py-1.5">
      <div className="flex items-center gap-2 text-sm">
        <IconSun size={16} className="text-muted-foreground" />
        <span>Theme</span>
      </div>
      <div className="flex items-center gap-0.5 rounded-lg border border-border bg-muted/50 p-0.5">
        {options.map(({ value, icon: Icon, label }) => {
          const isActive = theme === value;
          return (
            <button
              key={value}
              type="button"
              title={label}
              onClick={(e) => {
                e.preventDefault();
                e.stopPropagation();
                setTheme(value);
              }}
              className={`flex h-6 w-6 items-center justify-center rounded-md transition-all ${
                isActive
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              <Icon size={14} />
            </button>
          );
        })}
      </div>
    </div>
  );
}


export function NavUser({
  user,
}: {
  user: {
    name: string;
    email: string;
    avatar: string;
  };
}) {
  const router = useRouter();
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const {
    isSubscribed,
    planName,
    planId,
    loading: subLoading,
  } = useSubscription();

  const handleSignOut = async () => {
    setIsLoggingOut(true);
    try {
      await signOut();
      router.push("/login");
      router.refresh();
    } catch (error) {
      console.error("Sign out failed:", error);
      setIsLoggingOut(false);
    }
  };

  const getInitials = (name: string) => {
    return name
      .split(" ")
      .map((n) => n[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);
  };

  const getPlanBadge = () => {
    switch (planId) {
      case "pro":
        return {
          label: "Pro",
          className:
            "bg-purple-500/15 text-purple-400 border border-purple-500/30",
        };
      case "starter":
        return {
          label: "Starter",
          className: "bg-blue-500/15 text-blue-400 border border-blue-500/30",
        };
      case "enterprise":
        return {
          label: "Enterprise",
          className:
            "bg-amber-500/15 text-amber-400 border border-amber-500/30",
        };
      default:
        return null;
    }
  };

  const planBadge = getPlanBadge();

  return (
    <SidebarMenu>
      <SidebarMenuItem>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <SidebarMenuButton
              size="lg"
              className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
            >
              <div className="relative">
                <Avatar className="h-8 w-8 rounded-lg grayscale">
                  <AvatarImage src={user.avatar} alt={user.name} />
                  <AvatarFallback className="rounded-lg">
                    {getInitials(user.name)}
                  </AvatarFallback>
                </Avatar>
                {isSubscribed && (
                  <div className="absolute -top-1 -right-1 h-3 w-3 rounded-full bg-purple-500 border-2 border-sidebar" />
                )}
              </div>
              <div className="grid flex-1 text-left text-sm leading-tight">
                <div className="flex items-center gap-1.5">
                  <span className="truncate font-medium">{user.name}</span>
                  {!subLoading && planBadge && (
                    <span
                      className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider leading-none ${planBadge.className}`}
                    >
                      {planBadge.label}
                    </span>
                  )}
                </div>
              </div>
              <ChevronsUpDown className="ml-auto size-4" />
            </SidebarMenuButton>
          </DropdownMenuTrigger>
          <DropdownMenuContent
            className="w-(--radix-dropdown-menu-trigger-width) min-w-56 rounded-lg"
            side={"bottom"}
            align="end"
            sideOffset={4}
          >
            <DropdownMenuLabel className="p-0 font-normal">
              <div className="flex items-center gap-2 p-2 text-left text-sm bg-muted rounded-lg mb-3">
                <div className="relative">
                  <Avatar className="h-8 w-8 rounded-lg">
                    <AvatarImage src={user.avatar} alt={user.name} />
                    <AvatarFallback className="rounded-lg">
                      {getInitials(user.name)}
                    </AvatarFallback>
                  </Avatar>
                  {isSubscribed && (
                    <div className="absolute -bottom-0.5 -right-0.5">
                      <IconRosetteDiscountCheck
                        size={14}
                        className="text-purple-400 fill-purple-500/20"
                      />
                    </div>
                  )}
                </div>
                <div className="grid flex-1 text-left text-lg leading-tight">
                  <div className="flex items-center gap-2">
                    <span className="truncate font-medium cooper">
                      {user.name}
                    </span>
                    {!subLoading && planBadge && (
                      <span
                        className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-[9px] font-bold uppercase tracking-wider leading-none ${planBadge.className}`}
                      >
                        {planBadge.label}
                      </span>
                    )}
                  </div>
                  <span className="text-muted-foreground truncate text-xs">
                    {user.email}
                  </span>
                </div>
              </div>
            </DropdownMenuLabel>

            {!subLoading && isSubscribed && (
              <>
                <div className="flex items-center gap-2 px-2 py-1.5 mb-1 rounded-md bg-purple-500/5 border border-purple-500/10">
                  <IconSparkles
                    size={14}
                    className="text-purple-400 shrink-0"
                  />
                  <div className="flex flex-col min-w-0">
                    <span className="text-xs font-medium text-purple-300 dark:text-purple-300">
                      {planName} Plan Active
                    </span>
                    <span className="text-[10px] text-purple-400/60">
                      Subscribed via eSewa
                    </span>
                  </div>
                </div>
                <DropdownMenuSeparator />
              </>
            )}

            <DropdownMenuGroup className="space-y-1">
              <DropdownMenuItem
                className="cursor-pointer"
                onClick={() => router.push("/account?tab=profile")}
              >
                <IconUserCircle />
                Account
              </DropdownMenuItem>
              <DropdownMenuItem
                className="cursor-pointer"
                onClick={() => router.push("/account?tab=billing")}
              >
                <IconCoin />
                Billing
              </DropdownMenuItem>
              <DropdownMenuItem
                className="cursor-pointer"
                onClick={() => router.push("/account?tab=plan")}
              >
                {isSubscribed ? (
                  <>
                    <IconRosetteDiscountCheck className="text-purple-400" />
                    <span>Manage Plan</span>
                  </>
                ) : (
                  <>
                    <IconBolt />
                    <span>Upgrade</span>
                    <span className="ml-auto inline-flex items-center rounded-md bg-purple-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-purple-400 border border-purple-500/30">
                      PRO
                    </span>
                  </>
                )}
              </DropdownMenuItem>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={handleSignOut}
              disabled={isLoggingOut}
              className="cursor-pointer"
            >
              {isLoggingOut ? (
                <IconLoader2 className="animate-spin" />
              ) : (
                <IconLogout />
              )}
              {isLoggingOut ? "Signing out..." : "Log out"}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            {/* Theme switcher */}
            <ThemeSwitcher />
          </DropdownMenuContent>
        </DropdownMenu>
      </SidebarMenuItem>
    </SidebarMenu>
  );
}
