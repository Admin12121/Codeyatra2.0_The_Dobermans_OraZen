"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import { useSearchParams } from "next/navigation";
import {
  IconUserCircle,
  IconLock,
  IconFingerprint,
  IconShieldLock,
  IconCreditCard,
  IconChartBar,
  IconRocket,
  IconLoader2,
  IconCheck,
  IconX,
  IconPlus,
  IconTrash,
  IconCopy,
  IconAlertTriangle,
  IconEye,
  IconEyeOff,
  IconDeviceFloppy,
  IconKey,
  IconCalendar,
  IconChevronRight,
  IconInfoCircle,
} from "@tabler/icons-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { useSession, authClient, twoFactor, passkey } from "@/lib/auth-client";
import type { Session } from "@/lib/auth-client";
import {
  getCurrentOrganization,
  getOrganizationUsage,
} from "@/lib/actions/organization";
import {
  resolvePlan,
  formatLimit,
  isFreePlan,
  getUpgradePlan,
  formatNpr,
} from "@/lib/plans";
import {
  PricingCore,
  type VolumeTier,
  tiers,
} from "@/components/layout/landing/pricing";
import { useSubscription } from "@/hooks/use-subscription";


function usePrevious<T>(value: T): T | undefined {
  const [prev, setPrev] = useState<T | undefined>(undefined);
  const [current, setCurrent] = useState(value);
  if (value !== current) {
    setPrev(current);
    setCurrent(value);
  }
  return prev;
}

type SettingsTab =
  | "profile"
  | "password"
  | "passkeys"
  | "two-factor"
  | "plan"
  | "usage"
  | "billing";

interface PasskeyItem {
  id: string;
  name: string | null;
  createdAt: string;
  deviceType: string | null;
}

interface OrgInfo {
  id: string;
  name: string;
  slug: string;
  plan: string | null;
  createdAt: string;
}

interface UsageData {
  guardScansUsed: number;
  garakScansUsed: number;
  apiKeysUsed: number;
  modelConfigsUsed: number;
  threatsBlocked: number;
  avgLatencyMs: number;
  billingPeriodStart: string;
  billingPeriodEnd: string;
}

const TABS: {
  key: SettingsTab;
  label: string;
  icon: React.ElementType;
  group: string;
}[] = [
  { key: "profile", label: "Profile", icon: IconUserCircle, group: "Account" },
  { key: "password", label: "Password", icon: IconLock, group: "Account" },
  {
    key: "passkeys",
    label: "Passkeys",
    icon: IconFingerprint,
    group: "Security",
  },
  {
    key: "two-factor",
    label: "Two-Factor Auth",
    icon: IconShieldLock,
    group: "Security",
  },
  { key: "plan", label: "Current Plan", icon: IconRocket, group: "Billing" },
  { key: "usage", label: "Usage", icon: IconChartBar, group: "Billing" },
  {
    key: "billing",
    label: "Payment Details",
    icon: IconCreditCard,
    group: "Billing",
  },
];

const VALID_TABS: SettingsTab[] = [
  "profile",
  "password",
  "passkeys",
  "two-factor",
  "plan",
  "usage",
  "billing",
];

export default function AccountPage() {
  const { data: session, isPending: sessionLoading } = useSession();
  const searchParams = useSearchParams();
  const tabParam = searchParams.get("tab") as SettingsTab | null;
  const resolvedTab: SettingsTab = useMemo(
    () => (tabParam && VALID_TABS.includes(tabParam) ? tabParam : "profile"),
    [tabParam],
  );
  const [activeTab, setActiveTab] = useState<SettingsTab>(resolvedTab);

  const prevResolvedTab = usePrevious(resolvedTab);
  if (
    prevResolvedTab !== undefined &&
    prevResolvedTab !== resolvedTab &&
    activeTab !== resolvedTab
  ) {
    setActiveTab(resolvedTab);
  }

  if (sessionLoading) {
    return (
      <section className="px-4 py-6 w-full flex items-center justify-center min-h-[60vh]">
        <IconLoader2 className="animate-spin text-stone-500" size={32} />
      </section>
    );
  }

  if (!session) {
    return (
      <section className="px-4 py-6 w-full flex items-center justify-center min-h-[60vh]">
        <p className="text-stone-500 text-sm">
          Not authenticated. Please sign in.
        </p>
      </section>
    );
  }

  const groups = ["Account", "Security", "Billing"];

  return (
    <section className="px-4 py-6 w-full flex flex-col gap-6">
      <div>
        <h1 className="text-xl font-bold">Account Settings</h1>
        <p className="text-sm text-stone-500">
          Manage your profile, security, and billing preferences
        </p>
      </div>

      <div className="flex gap-6 min-h-[70vh]">
        <nav className="w-56 shrink-0 flex flex-col gap-1">
          {groups.map((group) => (
            <div key={group} className="mb-3">
              <span className="text-[10px] font-mono uppercase text-stone-500 px-3 mb-1 block tracking-wider">
                {group}
              </span>
              {TABS.filter((t) => t.group === group).map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.key;
                return (
                  <button
                    key={tab.key}
                    onClick={() => setActiveTab(tab.key)}
                    className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-all ${
                      isActive
                        ? "bg-stone-100 text-stone-800 font-medium"
                        : "text-stone-400 hover:text-stone-800 hover:bg-stone-100"
                    }`}
                  >
                    <Icon
                      size={16}
                      className={isActive ? "text-white" : "text-stone-500"}
                    />
                    {tab.label}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="flex-1 min-w-0">
          {activeTab === "profile" && <ProfileSection session={session} />}
          {activeTab === "password" && <PasswordSection />}
          {activeTab === "passkeys" && <PasskeysSection />}
          {activeTab === "two-factor" && <TwoFactorSection session={session} />}
          {activeTab === "plan" && <PlanSection />}
          {activeTab === "usage" && <UsageSection />}
          {activeTab === "billing" && <BillingSection />}
        </div>
      </div>
    </section>
  );
}

function SectionCard({
  title,
  description,
  icon: Icon,
  children,
}: {
  title: string;
  description: string;
  icon: React.ElementType;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-stone-50 border border-stone-200 rounded-xl overflow-hidden">
      <div className="px-6 py-5 border-b border-stone-200">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-stone-100">
            <Icon size={18} className="text-stone-400" />
          </div>
          <div>
            <h2 className="text-base font-semibold">{title}</h2>
            <p className="text-xs text-stone-500">{description}</p>
          </div>
        </div>
      </div>
      <div className="px-6 py-5">{children}</div>
    </div>
  );
}

function ProfileSection({ session }: { session: Session }) {
  const user = session.user;
  const [name, setName] = useState(user.name || "");
  const [email] = useState(user.email || "");
  const [image, setImage] = useState(user.image || "");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const getInitials = (n: string) =>
    n
      .split(" ")
      .map((w) => w[0])
      .join("")
      .toUpperCase()
      .slice(0, 2);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      await authClient.updateUser({
        name,
        image: image || undefined,
      });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update profile");
    } finally {
      setSaving(false);
    }
  };

  const createdAt = user.createdAt
    ? new Date(user.createdAt).toLocaleDateString("en-US", {
        year: "numeric",
        month: "long",
        day: "numeric",
      })
    : "Unknown";

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Profile Information"
        description="Update your name and avatar"
        icon={IconUserCircle}
      >
        <div className="flex flex-col gap-6">
          <div className="flex items-center gap-4">
            <Avatar className="h-16 w-16 rounded-xl">
              <AvatarImage src={image} alt={name} />
              <AvatarFallback className="rounded-xl text-lg bg-stone-100">
                {getInitials(name || email)}
              </AvatarFallback>
            </Avatar>
            <div className="flex flex-col gap-1">
              <span className="text-sm font-medium">
                {name || email.split("@")[0]}
              </span>
              <span className="text-xs text-stone-500">{email}</span>
              <div className="flex items-center gap-1.5 mt-0.5">
                <IconCalendar size={12} className="text-stone-600" />
                <span className="text-[11px] text-stone-600">
                  Joined {createdAt}
                </span>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="flex flex-col gap-2">
              <Label htmlFor="profile-name" className="text-xs text-stone-400">
                Display Name
              </Label>
              <Input
                id="profile-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Your name"
                className="bg-stone-100 border-stone-300"
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="profile-email" className="text-xs text-stone-400">
                Email Address
              </Label>
              <div className="relative">
                <Input
                  id="profile-email"
                  value={email}
                  disabled
                  className="bg-stone-100 border-stone-300 text-stone-500 pr-20"
                />
                <div className="absolute right-2 top-1/2 -translate-y-1/2">
                  {user.emailVerified ? (
                    <Badge className="bg-emerald-500/15 text-emerald-400 border-emerald-500/30 text-[10px]">
                      Verified
                    </Badge>
                  ) : (
                    <Badge className="bg-amber-500/15 text-amber-400 border-amber-500/30 text-[10px]">
                      Unverified
                    </Badge>
                  )}
                </div>
              </div>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <Label htmlFor="profile-avatar" className="text-xs text-stone-400">
              Avatar URL
            </Label>
            <Input
              id="profile-avatar"
              value={image}
              onChange={(e) => setImage(e.target.value)}
              placeholder="https://example.com/avatar.png"
              className="bg-stone-100 border-stone-300"
            />
            <span className="text-[11px] text-stone-600">
              Paste a direct link to an image. Leave blank to use initials.
            </span>
          </div>

          {error && (
            <div className="flex items-center gap-2 text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
              <IconX size={14} />
              <span className="text-xs">{error}</span>
            </div>
          )}

          <div className="flex items-center justify-end gap-3 pt-2 border-t border-stone-200">
            {saved && (
              <span className="text-xs text-emerald-400 flex items-center gap-1">
                <IconCheck size={14} /> Saved
              </span>
            )}
            <Button onClick={handleSave} disabled={saving} size="sm">
              {saving ? (
                <IconLoader2 size={14} className="animate-spin" />
              ) : (
                <IconDeviceFloppy size={14} />
              )}
              {saving ? "Saving..." : "Save Changes"}
            </Button>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}

function PasswordSection() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const passwordsMatch = newPassword === confirmPassword;
  const passwordStrong = newPassword.length >= 8;

  const handleChangePassword = async () => {
    if (!passwordsMatch) {
      setError("Passwords do not match");
      return;
    }
    if (!passwordStrong) {
      setError("Password must be at least 8 characters");
      return;
    }
    setSaving(true);
    setError(null);
    setSaved(false);
    try {
      await authClient.changePassword({
        currentPassword,
        newPassword,
      });
      setSaved(true);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      setTimeout(() => setSaved(false), 3000);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to change password",
      );
    } finally {
      setSaving(false);
    }
  };

  return (
    <SectionCard
      title="Change Password"
      description="Update your account password"
      icon={IconLock}
    >
      <div className="flex flex-col gap-5 max-w-md">
        <div className="flex flex-col gap-2">
          <Label htmlFor="current-pw" className="text-xs text-stone-400">
            Current Password
          </Label>
          <div className="relative">
            <Input
              id="current-pw"
              type={showCurrent ? "text" : "password"}
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
              placeholder="••••••••"
              className="bg-stone-100 border-stone-300 pr-10"
            />
            <button
              type="button"
              onClick={() => setShowCurrent(!showCurrent)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-stone-500 hover:text-stone-700"
            >
              {showCurrent ? <IconEyeOff size={16} /> : <IconEye size={16} />}
            </button>
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <Label htmlFor="new-pw" className="text-xs text-stone-400">
            New Password
          </Label>
          <div className="relative">
            <Input
              id="new-pw"
              type={showNew ? "text" : "password"}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="••••••••"
              className="bg-stone-100 border-stone-300 pr-10"
            />
            <button
              type="button"
              onClick={() => setShowNew(!showNew)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-stone-500 hover:text-stone-700"
            >
              {showNew ? <IconEyeOff size={16} /> : <IconEye size={16} />}
            </button>
          </div>
          {newPassword.length > 0 && (
            <div className="flex items-center gap-2 mt-1">
              <div className="flex gap-1 flex-1">
                {[1, 2, 3, 4].map((i) => (
                  <div
                    key={i}
                    className={`h-1 flex-1 rounded-full ${
                      newPassword.length >= i * 3
                        ? newPassword.length >= 12
                          ? "bg-emerald-500"
                          : newPassword.length >= 8
                            ? "bg-amber-500"
                            : "bg-red-500"
                        : "bg-stone-200"
                    }`}
                  />
                ))}
              </div>
              <span className="text-[10px] text-stone-500 font-mono">
                {newPassword.length >= 12
                  ? "Strong"
                  : newPassword.length >= 8
                    ? "Fair"
                    : "Weak"}
              </span>
            </div>
          )}
        </div>

        <div className="flex flex-col gap-2">
          <Label htmlFor="confirm-pw" className="text-xs text-stone-400">
            Confirm New Password
          </Label>
          <Input
            id="confirm-pw"
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            placeholder="••••••••"
            className={`bg-stone-100 border-stone-300 ${
              confirmPassword.length > 0 && !passwordsMatch
                ? "border-red-500/50 focus:border-red-500"
                : ""
            }`}
          />
          {confirmPassword.length > 0 && !passwordsMatch && (
            <span className="text-[11px] text-red-400">
              Passwords do not match
            </span>
          )}
        </div>

        {error && (
          <div className="flex items-center gap-2 text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
            <IconX size={14} />
            <span className="text-xs">{error}</span>
          </div>
        )}

        <div className="flex items-center justify-end gap-3 pt-3 border-t border-stone-200">
          {saved && (
            <span className="text-xs text-emerald-400 flex items-center gap-1">
              <IconCheck size={14} /> Password changed
            </span>
          )}
          <Button
            onClick={handleChangePassword}
            disabled={
              saving || !currentPassword || !newPassword || !confirmPassword
            }
            size="sm"
          >
            {saving ? (
              <IconLoader2 size={14} className="animate-spin" />
            ) : (
              <IconLock size={14} />
            )}
            {saving ? "Updating..." : "Update Password"}
          </Button>
        </div>
      </div>
    </SectionCard>
  );
}

function PasskeysSection() {
  const [passkeys, setPasskeys] = useState<PasskeyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [registering, setRegistering] = useState(false);
  const [passkeyName, setPasskeyName] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const fetchPasskeys = useCallback(async () => {
    setLoading(true);
    try {
      const res = await passkey.listUserPasskeys();
      if (res?.data) {
        const items = Array.isArray(res.data) ? res.data : [];
        setPasskeys(
          items.map((p) => ({
            id: p.id,
            name: p.name ?? null,
            createdAt:
              typeof p.createdAt === "string"
                ? p.createdAt
                : new Date(p.createdAt).toISOString(),
            deviceType: p.deviceType ?? null,
          })),
        );
      }
    } catch {
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchPasskeys();
  }, [fetchPasskeys]);

  const handleRegister = async () => {
    setRegistering(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await passkey.addPasskey({
        name: passkeyName || undefined,
      });
      if (res?.error) {
        setError(res.error.message || "Failed to register passkey");
      } else {
        setSuccess("Passkey registered successfully");
        setShowAdd(false);
        setPasskeyName("");
        fetchPasskeys();
        setTimeout(() => setSuccess(null), 3000);
      }
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to register passkey",
      );
    } finally {
      setRegistering(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await passkey.deletePasskey({ id });
      fetchPasskeys();
    } catch {
      setError("Failed to delete passkey");
    }
  };

  return (
    <SectionCard
      title="Passkeys"
      description="Use biometric authentication for passwordless sign-in"
      icon={IconFingerprint}
    >
      <div className="flex flex-col gap-4">
        <div className="flex items-start gap-3 bg-blue-500/5 border border-blue-500/20 rounded-lg px-4 py-3">
          <IconInfoCircle size={16} className="text-blue-400 mt-0.5 shrink-0" />
          <p className="text-xs text-blue-300/80 leading-relaxed">
            Passkeys let you sign in with fingerprint, face recognition, or
            device PIN. They are phishing-resistant and more secure than
            passwords.
          </p>
        </div>
        {loading ? (
          <div className="flex items-center justify-center py-8">
            <IconLoader2 className="animate-spin text-stone-500" size={20} />
          </div>
        ) : passkeys.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-8 gap-2">
            <IconFingerprint size={32} className="text-stone-600" />
            <p className="text-sm text-stone-500">No passkeys registered</p>
            <p className="text-xs text-stone-600">
              Add a passkey to enable passwordless sign-in
            </p>
          </div>
        ) : (
          <div className="flex flex-col gap-2">
            {passkeys.map((pk) => (
              <div
                key={pk.id}
                className="flex items-center justify-between bg-stone-100 border border-stone-300 rounded-lg px-4 py-3"
              >
                <div className="flex items-center gap-3">
                  <div className="p-1.5 rounded-md bg-stone-200">
                    <IconKey size={14} className="text-stone-400" />
                  </div>
                  <div>
                    <span className="text-sm font-medium">
                      {pk.name || "Unnamed passkey"}
                    </span>
                    <div className="flex items-center gap-2 mt-0.5">
                      {pk.deviceType && (
                        <span className="text-[10px] font-mono text-stone-500 bg-stone-200/50 px-1.5 py-0.5 rounded">
                          {pk.deviceType}
                        </span>
                      )}
                      <span className="text-[10px] text-stone-600">
                        Added{" "}
                        {new Date(pk.createdAt).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })}
                      </span>
                    </div>
                  </div>
                </div>
                <AlertDialog>
                  <AlertDialogTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      className="text-stone-500 hover:text-red-400"
                    >
                      <IconTrash size={14} />
                    </Button>
                  </AlertDialogTrigger>
                  <AlertDialogContent>
                    <AlertDialogHeader>
                      <AlertDialogTitle>Remove passkey?</AlertDialogTitle>
                      <AlertDialogDescription>
                        You will no longer be able to sign in with this passkey.
                        This action cannot be undone.
                      </AlertDialogDescription>
                    </AlertDialogHeader>
                    <AlertDialogFooter>
                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                      <AlertDialogAction onClick={() => handleDelete(pk.id)}>
                        Remove
                      </AlertDialogAction>
                    </AlertDialogFooter>
                  </AlertDialogContent>
                </AlertDialog>
              </div>
            ))}
          </div>
        )}
        {showAdd ? (
          <div className="flex flex-col gap-3 bg-stone-100 border border-stone-300 rounded-lg p-4">
            <Label htmlFor="passkey-name" className="text-xs text-stone-400">
              Passkey Name (optional)
            </Label>
            <Input
              id="passkey-name"
              value={passkeyName}
              onChange={(e) => setPasskeyName(e.target.value)}
              placeholder="e.g. MacBook Pro, iPhone"
              className="bg-stone-100 border-stone-300"
            />
            <div className="flex gap-2 justify-end">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setShowAdd(false);
                  setPasskeyName("");
                }}
              >
                Cancel
              </Button>
              <Button size="sm" onClick={handleRegister} disabled={registering}>
                {registering ? (
                  <IconLoader2 size={14} className="animate-spin" />
                ) : (
                  <IconFingerprint size={14} />
                )}
                {registering ? "Registering..." : "Register Passkey"}
              </Button>
            </div>
          </div>
        ) : (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowAdd(true)}
            className="self-start"
          >
            <IconPlus size={14} />
            Add Passkey
          </Button>
        )}

        {error && (
          <div className="flex items-center gap-2 text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
            <IconX size={14} />
            <span className="text-xs">{error}</span>
          </div>
        )}
        {success && (
          <div className="flex items-center gap-2 text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2">
            <IconCheck size={14} />
            <span className="text-xs">{success}</span>
          </div>
        )}
      </div>
    </SectionCard>
  );
}

function TwoFactorSection({ session }: { session: Session }) {
  const is2FAEnabled = session.user.twoFactorEnabled ?? false;
  const [enabling, setEnabling] = useState(false);
  const [disabling, setDisabling] = useState(false);
  const [totpURI, setTotpURI] = useState<string | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [verifyCode, setVerifyCode] = useState("");
  const [step, setStep] = useState<"idle" | "setup" | "verify" | "backup">(
    "idle",
  );
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [disablePassword, setDisablePassword] = useState("");
  const [copiedBackup, setCopiedBackup] = useState(false);

  const handleEnable2FA = async () => {
    setEnabling(true);
    setError(null);
    try {
      const res = await twoFactor.enable({
        password: verifyCode,
      });
      if (res?.error) {
        setError(res.error.message || "Failed to enable 2FA");
        setEnabling(false);
        return;
      }
      if (res?.data) {
        const d = res.data as Record<string, unknown>;
        setTotpURI(typeof d.totpURI === "string" ? d.totpURI : null);
        setBackupCodes(
          Array.isArray(d.backupCodes) ? (d.backupCodes as string[]) : [],
        );
        setStep("setup");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to enable 2FA");
    } finally {
      setEnabling(false);
    }
  };

  const handleVerifyTOTP = async () => {
    setError(null);
    try {
      const res = await twoFactor.verifyTotp({
        code: verifyCode,
      });
      if (res?.error) {
        setError(res.error.message || "Invalid code");
        return;
      }
      setStep("backup");
      setSuccess("Two-factor authentication enabled!");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Verification failed");
    }
  };

  const handleDisable2FA = async () => {
    setDisabling(true);
    setError(null);
    try {
      const res = await twoFactor.disable({
        password: disablePassword,
      });
      if (res?.error) {
        setError(res.error.message || "Failed to disable 2FA");
      } else {
        setSuccess("Two-factor authentication disabled");
        setDisablePassword("");
        setTimeout(() => setSuccess(null), 3000);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to disable 2FA");
    } finally {
      setDisabling(false);
    }
  };

  const copyBackupCodes = () => {
    navigator.clipboard.writeText(backupCodes.join("\n"));
    setCopiedBackup(true);
    setTimeout(() => setCopiedBackup(false), 2000);
  };

  return (
    <SectionCard
      title="Two-Factor Authentication"
      description="Add an extra layer of security to your account"
      icon={IconShieldLock}
    >
      <div className="flex flex-col gap-5">
        <div className="flex items-center justify-between bg-stone-100 border border-stone-300 rounded-lg px-4 py-3">
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-lg ${
                is2FAEnabled ? "bg-emerald-500/15" : "bg-stone-200"
              }`}
            >
              <IconShieldLock
                size={18}
                className={is2FAEnabled ? "text-emerald-400" : "text-stone-500"}
              />
            </div>
            <div>
              <span className="text-sm font-medium">
                {is2FAEnabled ? "2FA is enabled" : "2FA is not enabled"}
              </span>
              <p className="text-xs text-stone-500">
                {is2FAEnabled
                  ? "Your account is protected with TOTP authentication"
                  : "Enable two-factor authentication for additional security"}
              </p>
            </div>
          </div>
          <Badge
            className={
              is2FAEnabled
                ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                : "bg-stone-200 text-stone-400 border-stone-300"
            }
          >
            {is2FAEnabled ? "Active" : "Inactive"}
          </Badge>
        </div>

        {!is2FAEnabled && step === "idle" && (
          <div className="flex flex-col gap-3 max-w-md">
            <p className="text-xs text-stone-400 leading-relaxed">
              Enter your account password to begin two-factor setup. You will
              need an authenticator app like Google Authenticator, Authy, or
              1Password.
            </p>
            <div className="flex flex-col gap-2">
              <Label htmlFor="2fa-password" className="text-xs text-stone-400">
                Account Password
              </Label>
              <Input
                id="2fa-password"
                type="password"
                value={verifyCode}
                onChange={(e) => setVerifyCode(e.target.value)}
                placeholder="Enter your password"
                className="bg-stone-100 border-stone-300"
              />
            </div>
            <Button
              onClick={handleEnable2FA}
              disabled={enabling || !verifyCode}
              size="sm"
              className="self-start"
            >
              {enabling ? (
                <IconLoader2 size={14} className="animate-spin" />
              ) : (
                <IconShieldLock size={14} />
              )}
              {enabling ? "Setting up..." : "Enable 2FA"}
            </Button>
          </div>
        )}

        {step === "setup" && totpURI && (
          <div className="flex flex-col gap-4 max-w-md">
            <div className="bg-stone-100 border border-stone-300 rounded-lg p-4">
              <h3 className="text-sm font-medium mb-2">Scan QR Code</h3>
              <p className="text-xs text-stone-400 mb-3">
                Scan this QR code with your authenticator app, then enter the
                6-digit code below to verify.
              </p>
              <div className="bg-white p-4 rounded-lg inline-block">
                <img
                  src={`https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(totpURI)}&size=200x200`}
                  alt="2FA QR Code"
                  width={200}
                  height={200}
                />
              </div>
              <div className="mt-3">
                <span className="text-[10px] text-stone-500 font-mono">
                  Manual entry:
                </span>
                <p className="text-xs font-mono text-stone-400 break-all bg-stone-50 rounded p-2 mt-1">
                  {totpURI}
                </p>
              </div>
            </div>

            <div className="flex flex-col gap-2">
              <Label htmlFor="totp-code" className="text-xs text-stone-400">
                Verification Code
              </Label>
              <Input
                id="totp-code"
                value={verifyCode}
                onChange={(e) =>
                  setVerifyCode(e.target.value.replace(/\D/g, "").slice(0, 6))
                }
                placeholder="000000"
                maxLength={6}
                className="bg-stone-100 border-stone-300 font-mono text-center text-lg tracking-widest max-w-[200px]"
              />
            </div>

            <div className="flex gap-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setStep("idle");
                  setTotpURI(null);
                  setVerifyCode("");
                }}
              >
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={handleVerifyTOTP}
                disabled={verifyCode.length !== 6}
              >
                Verify & Enable
              </Button>
            </div>
          </div>
        )}

        {step === "backup" && backupCodes.length > 0 && (
          <div className="flex flex-col gap-4 max-w-md">
            <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-2">
                <IconAlertTriangle size={16} className="text-amber-400" />
                <h3 className="text-sm font-medium text-amber-300">
                  Save Backup Codes
                </h3>
              </div>
              <p className="text-xs text-amber-200/60 mb-3">
                Store these backup codes in a safe place. Each code can only be
                used once to sign in if you lose access to your authenticator
                app.
              </p>
              <div className="grid grid-cols-2 gap-1.5 bg-stone-50 rounded-lg p-3">
                {backupCodes.map((code, i) => (
                  <span
                    key={i}
                    className="text-xs font-mono text-stone-700 text-center py-1"
                  >
                    {code}
                  </span>
                ))}
              </div>
              <Button
                variant="outline"
                size="sm"
                className="mt-3"
                onClick={copyBackupCodes}
              >
                {copiedBackup ? (
                  <IconCheck size={14} />
                ) : (
                  <IconCopy size={14} />
                )}
                {copiedBackup ? "Copied!" : "Copy Codes"}
              </Button>
            </div>
            <Button
              size="sm"
              className="self-start"
              onClick={() => setStep("idle")}
            >
              Done
            </Button>
          </div>
        )}

        {is2FAEnabled && (
          <div className="flex flex-col gap-3 pt-3 border-t border-stone-200 max-w-md">
            <h3 className="text-sm font-medium text-stone-700">
              Disable Two-Factor
            </h3>
            <p className="text-xs text-stone-500">
              Enter your password to disable two-factor authentication. This
              will make your account less secure.
            </p>
            <div className="flex flex-col gap-2">
              <Input
                type="password"
                value={disablePassword}
                onChange={(e) => setDisablePassword(e.target.value)}
                placeholder="Enter your password"
                className="bg-stone-100 border-stone-300"
              />
            </div>
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button
                  variant="destructive"
                  size="sm"
                  className="self-start"
                  disabled={!disablePassword}
                >
                  Disable 2FA
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>
                    Disable two-factor authentication?
                  </AlertDialogTitle>
                  <AlertDialogDescription>
                    This will remove the extra layer of security from your
                    account. You can always re-enable it later.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction onClick={handleDisable2FA}>
                    {disabling ? "Disabling..." : "Disable"}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </div>
        )}

        {error && (
          <div className="flex items-center gap-2 text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
            <IconX size={14} />
            <span className="text-xs">{error}</span>
          </div>
        )}
        {success && (
          <div className="flex items-center gap-2 text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-3 py-2">
            <IconCheck size={14} />
            <span className="text-xs">{success}</span>
          </div>
        )}
      </div>
    </SectionCard>
  );
}


function PlanSection() {
  const [org, setOrg] = useState<OrgInfo | null>(null);
  const [usage, setUsage] = useState<UsageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedTier, setSelectedTier] = useState<VolumeTier>(tiers[2]);
  const { planId: subPlanId, isSubscribed } = useSubscription();

  useEffect(() => {
    (async () => {
      try {
        const [orgData, usageData] = await Promise.allSettled([
          getCurrentOrganization(),
          getOrganizationUsage(),
        ]);

        if (orgData.status === "fulfilled" && orgData.value) {
          setOrg({
            id: orgData.value.id,
            name: orgData.value.name,
            slug: orgData.value.slug,
            plan: orgData.value.plan,
            createdAt: orgData.value.created_at,
          });
        }

        if (usageData.status === "fulfilled" && usageData.value) {
          setUsage({
            guardScansUsed: usageData.value.guardScansUsed,
            garakScansUsed: usageData.value.garakScansUsed,
            apiKeysUsed: usageData.value.apiKeysUsed,
            modelConfigsUsed: usageData.value.modelConfigsUsed,
            threatsBlocked: usageData.value.threatsBlocked,
            avgLatencyMs: usageData.value.avgLatencyMs,
            billingPeriodStart: usageData.value.billingPeriodStart,
            billingPeriodEnd: usageData.value.billingPeriodEnd,
          });
        }
      } catch {
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const effectivePlanStr = isSubscribed ? subPlanId : (org?.plan ?? subPlanId);
  const currentPlan = resolvePlan(effectivePlanStr);
  const previewPlanStr = selectedTier.full.tier;
  const previewPlan = resolvePlan(previewPlanStr);
  const previewGuardScans = selectedTier.value === -1 ? -1 : selectedTier.value;
  const previewGarakScans = previewPlan.limits.garakScans;
  const previewApiKeys = previewPlan.limits.apiKeys;
  const previewModelConfigs = previewPlan.limits.modelConfigs;

  const handleTierChange = useCallback((tier: VolumeTier) => {
    setSelectedTier(tier);
  }, []);

  if (loading) {
    return (
      <SectionCard
        title="Current Plan"
        description="Your subscription details"
        icon={IconRocket}
      >
        <div className="flex items-center justify-center py-12">
          <IconLoader2 className="animate-spin text-stone-500" size={24} />
        </div>
      </SectionCard>
    );
  }

  return (
    <SectionCard
      title="Current Plan"
      description="Your subscription and upgrade options"
      icon={IconRocket}
    >
      <div className="flex flex-col gap-6">
        {org && (
          <div className="flex items-center gap-4 bg-stone-100 border border-stone-300 rounded-lg px-4 py-3">
            <div className="p-2 rounded-lg bg-stone-200">
              <IconRocket size={18} className="text-stone-400" />
            </div>
            <div className="flex-1">
              <span className="text-sm font-medium">
                Organization: {org.name}
              </span>
              <p className="text-xs text-stone-500">
                Created{" "}
                {new Date(org.createdAt).toLocaleDateString("en-US", {
                  month: "long",
                  day: "numeric",
                  year: "numeric",
                })}
              </p>
            </div>
            <Badge
              className={`${currentPlan.badgeClass} uppercase text-[10px] tracking-wider`}
            >
              {currentPlan.name}
            </Badge>
          </div>
        )}

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="bg-stone-100 border border-stone-300 rounded-lg px-3 py-2.5 text-center">
            <span className="text-sm font-bold font-mono text-stone-800">
              {(usage?.guardScansUsed ?? 0).toLocaleString()}
            </span>
            <span className="text-[10px] text-stone-600 font-mono">
              {" "}
              / {formatLimit(previewGuardScans)}
            </span>
            <p className="text-[9px] text-stone-500 uppercase font-mono mt-0.5">
              Guard Scans
            </p>
          </div>
          <div className="bg-stone-100 border border-stone-300 rounded-lg px-3 py-2.5 text-center">
            <span className="text-sm font-bold font-mono text-stone-800">
              {usage?.garakScansUsed ?? 0}
            </span>
            <span className="text-[10px] text-stone-600 font-mono">
              {" "}
              / {formatLimit(previewGarakScans)}
            </span>
            <p className="text-[9px] text-stone-500 uppercase font-mono mt-0.5">
              Garak Scans
            </p>
          </div>
          <div className="bg-stone-100 border border-stone-300 rounded-lg px-3 py-2.5 text-center">
            <span className="text-sm font-bold font-mono text-stone-800">
              {usage?.apiKeysUsed ?? 0}
            </span>
            <span className="text-[10px] text-stone-600 font-mono">
              {" "}
              / {formatLimit(previewApiKeys)}
            </span>
            <p className="text-[9px] text-stone-500 uppercase font-mono mt-0.5">
              API Keys
            </p>
          </div>
          <div className="bg-stone-100 border border-stone-300 rounded-lg px-3 py-2.5 text-center">
            <span className="text-sm font-bold font-mono text-stone-800">
              {usage?.modelConfigsUsed ?? 0}
            </span>
            <span className="text-[10px] text-stone-600 font-mono">
              {" "}
              / {formatLimit(previewModelConfigs)}
            </span>
            <p className="text-[9px] text-stone-500 uppercase font-mono mt-0.5">
              Models
            </p>
          </div>
        </div>
        <PricingCore
          variant="dashboard"
          defaultIndex={2}
          onTierChange={handleTierChange}
        />
      </div>
    </SectionCard>
  );
}


function UsageSection() {
  const [org, setOrg] = useState<OrgInfo | null>(null);
  const [usage, setUsage] = useState<UsageData | null>(null);
  const [loading, setLoading] = useState(true);
  const { planId: subPlanId, isSubscribed } = useSubscription();

  useEffect(() => {
    (async () => {
      try {
        const [orgData, usageData] = await Promise.allSettled([
          getCurrentOrganization(),
          getOrganizationUsage(),
        ]);

        if (orgData.status === "fulfilled" && orgData.value) {
          setOrg({
            id: orgData.value.id,
            name: orgData.value.name,
            slug: orgData.value.slug,
            plan: orgData.value.plan,
            createdAt: orgData.value.created_at,
          });
        }

        if (usageData.status === "fulfilled" && usageData.value) {
          setUsage({
            guardScansUsed: usageData.value.guardScansUsed,
            garakScansUsed: usageData.value.garakScansUsed,
            apiKeysUsed: usageData.value.apiKeysUsed,
            modelConfigsUsed: usageData.value.modelConfigsUsed,
            threatsBlocked: usageData.value.threatsBlocked,
            avgLatencyMs: usageData.value.avgLatencyMs,
            billingPeriodStart: usageData.value.billingPeriodStart,
            billingPeriodEnd: usageData.value.billingPeriodEnd,
          });
        }
      } catch {
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const effectivePlanStr = isSubscribed ? subPlanId : (org?.plan ?? subPlanId);
  const currentPlan = resolvePlan(effectivePlanStr);
  const limits = currentPlan.limits;

  const usageItems: {
    label: string;
    used: number;
    limit: number;
    icon: React.ElementType;
  }[] = [
    {
      label: "Guard Scans",
      used: usage?.guardScansUsed ?? 0,
      limit: limits.guardScans,
      icon: IconShieldLock,
    },
    {
      label: "Garak Scans",
      used: usage?.garakScansUsed ?? 0,
      limit: limits.garakScans,
      icon: IconChartBar,
    },
    {
      label: "API Keys",
      used: usage?.apiKeysUsed ?? 0,
      limit: limits.apiKeys,
      icon: IconKey,
    },
    {
      label: "Model Configs",
      used: usage?.modelConfigsUsed ?? 0,
      limit: limits.modelConfigs,
      icon: IconRocket,
    },
  ];

  if (loading) {
    return (
      <SectionCard
        title="Usage"
        description="Current billing period usage"
        icon={IconChartBar}
      >
        <div className="flex items-center justify-center py-12">
          <IconLoader2 className="animate-spin text-stone-500" size={24} />
        </div>
      </SectionCard>
    );
  }

  const billingPeriodLabel = usage
    ? `${new Date(usage.billingPeriodStart).toLocaleDateString("en-US", { month: "short", day: "numeric" })} — ${new Date(usage.billingPeriodEnd).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}`
    : new Date().toLocaleDateString("en-US", {
        month: "long",
        year: "numeric",
      });

  return (
    <SectionCard
      title="Usage"
      description="Current billing period usage"
      icon={IconChartBar}
    >
      <div className="flex flex-col gap-5">
        <div className="flex items-center justify-between">
          <div>
            <span className="text-sm font-medium">Billing Period</span>
            <p className="text-xs text-stone-500">{billingPeriodLabel}</p>
          </div>
          <Badge className={`${currentPlan.badgeClass} uppercase text-[10px]`}>
            {currentPlan.name}
          </Badge>
        </div>

        {usage && usage.guardScansUsed > 0 && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <div className="bg-stone-100 border border-stone-300 rounded-lg px-3 py-2.5 text-center">
              <span className="text-lg font-bold font-mono text-stone-800">
                {usage.guardScansUsed.toLocaleString()}
              </span>
              <p className="text-[10px] text-stone-500 uppercase font-mono mt-0.5">
                Total Scans
              </p>
            </div>
            <div className="bg-stone-100 border border-stone-300 rounded-lg px-3 py-2.5 text-center">
              <span className="text-lg font-bold font-mono text-red-400">
                {usage.threatsBlocked.toLocaleString()}
              </span>
              <p className="text-[10px] text-stone-500 uppercase font-mono mt-0.5">
                Threats Blocked
              </p>
            </div>
            <div className="bg-stone-100 border border-stone-300 rounded-lg px-3 py-2.5 text-center">
              <span className="text-lg font-bold font-mono text-emerald-400">
                {(usage.guardScansUsed - usage.threatsBlocked).toLocaleString()}
              </span>
              <p className="text-[10px] text-stone-500 uppercase font-mono mt-0.5">
                Safe Prompts
              </p>
            </div>
            <div className="bg-stone-100 border border-stone-300 rounded-lg px-3 py-2.5 text-center">
              <span className="text-lg font-bold font-mono text-blue-400">
                {usage.avgLatencyMs}ms
              </span>
              <p className="text-[10px] text-stone-500 uppercase font-mono mt-0.5">
                Avg Latency
              </p>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {usageItems.map((item) => {
            const Icon = item.icon;
            const isUnlimited = item.limit === -1;
            const pct = isUnlimited
              ? 0
              : item.limit === 0
                ? 100
                : Math.min((item.used / item.limit) * 100, 100);
            const limitStr = formatLimit(item.limit);

            return (
              <div
                key={item.label}
                className="bg-stone-100 border border-stone-300 rounded-lg p-4"
              >
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Icon size={16} className="text-stone-500" />
                    <span className="text-sm font-medium">{item.label}</span>
                  </div>
                  <span className="text-xs font-mono text-stone-500">
                    {item.used.toLocaleString()} / {limitStr}
                  </span>
                </div>
                <div className="w-full bg-stone-200 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full transition-all ${
                      isUnlimited
                        ? "bg-emerald-500"
                        : pct > 90
                          ? "bg-red-500"
                          : pct > 70
                            ? "bg-amber-500"
                            : "bg-emerald-500"
                    }`}
                    style={{
                      width: `${isUnlimited ? 100 : Math.max(pct, 1)}%`,
                    }}
                  />
                </div>
                <span className="text-[10px] text-stone-600 mt-1 block">
                  {isUnlimited ? "Unlimited" : `${pct.toFixed(1)}% used`}
                </span>
              </div>
            );
          })}
        </div>

        {isFreePlan(effectivePlanStr) && (
          <div className="flex items-start gap-3 bg-amber-500/5 border border-amber-500/20 rounded-lg px-4 py-3">
            <IconAlertTriangle
              size={16}
              className="text-amber-400 mt-0.5 shrink-0"
            />
            <div>
              <p className="text-xs text-amber-300/80">
                You&apos;re on the <strong>Free Trial</strong> (15 days).
                Upgrade to <strong>Starter</strong> (रू 1,500/महिना) or{" "}
                <strong>Pro</strong> (रू 6,900/महिना) for higher limits and
                advanced features. Pay securely with eSewa.
              </p>
              <Button
                variant="link"
                size="sm"
                className="p-0 h-auto text-amber-400 text-xs mt-1"
              >
                View upgrade options <IconChevronRight size={12} />
              </Button>
            </div>
          </div>
        )}
      </div>
    </SectionCard>
  );
}

function BillingSection() {
  const {
    subscription: sub,
    isSubscribed,
    planId,
    loading: subLoading,
  } = useSubscription();

  const currentPlan = resolvePlan(planId);
  const upgradePlan = getUpgradePlan(planId);
  const isFree = isFreePlan(planId);

  const lastPayment = sub?.lastPayment ?? null;
  const periodStart = sub?.currentPeriodStart
    ? new Date(sub.currentPeriodStart)
    : null;
  const periodEnd = sub?.currentPeriodEnd
    ? new Date(sub.currentPeriodEnd)
    : null;

  const formatDate = (d: Date) =>
    d.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      year: "numeric",
    });

  if (subLoading) {
    return (
      <SectionCard
        title="Payment & Billing"
        description="Manage your subscription and payments"
        icon={IconCreditCard}
      >
        <div className="flex items-center justify-center py-12">
          <IconLoader2 className="animate-spin text-stone-500" size={24} />
        </div>
      </SectionCard>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      <SectionCard
        title="Subscription"
        description="Your current plan and billing summary"
        icon={IconCreditCard}
      >
        <div className="flex flex-col gap-5">
          <div className="flex items-center justify-between bg-stone-100 border border-stone-300 rounded-lg px-4 py-3">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-stone-200">
                <IconRocket size={16} className="text-stone-400" />
              </div>
              <div>
                <span className="text-sm font-medium">{currentPlan.name}</span>
                <p className="text-xs text-stone-500">
                  {currentPlan.price}
                  {currentPlan.period}
                  {currentPlan.durationNote
                    ? ` · ${currentPlan.durationNote}`
                    : ""}
                </p>
              </div>
            </div>
            <Badge
              className={`${currentPlan.badgeClass} uppercase text-[10px]`}
            >
              {currentPlan.name}
            </Badge>
          </div>

          {isSubscribed && periodStart && periodEnd && (
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-stone-100 border border-stone-300 rounded-lg px-3 py-2.5">
                <p className="text-[10px] text-stone-500 uppercase font-mono mb-0.5">
                  Period Start
                </p>
                <span className="text-sm font-medium font-mono text-stone-800">
                  {formatDate(periodStart)}
                </span>
              </div>
              <div className="bg-stone-100 border border-stone-300 rounded-lg px-3 py-2.5">
                <p className="text-[10px] text-stone-500 uppercase font-mono mb-0.5">
                  Period End
                </p>
                <span className="text-sm font-medium font-mono text-stone-800">
                  {formatDate(periodEnd)}
                </span>
              </div>
            </div>
          )}

          <div className="flex items-center justify-between border-t border-stone-200 pt-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-[#60BB46]/10">
                <svg
                  width="20"
                  height="20"
                  viewBox="16 16 160 160"
                  fill="none"
                  xmlns="http://www.w3.org/2000/svg"
                  className="shrink-0"
                >
                  <path
                    fill="#5CBF41"
                    d="M96 36a60 60 0 00-60 60 60 60 0 0060 60 60 60 0 0059.57-54H133V90h22.697A60 60 0 0096 36z"
                  />
                  <path
                    fill="#ffffff"
                    d="M94.99 60c-11.395.028-20.651 4.787-26.39 13.332a46.5 46.5 0 00-3.704 7.32c-2.62 9.187-2.461 17.944.083 26.44 1.009 3.335 2.82 7.405 4.328 9.727 8.421 12.298 20.987 16.487 34.375 12.998 8.24-2.285 14.173-7.415 18.158-15.7 2.349-4.882 2.664-7.004 1.129-7.593-1.957-.75-2.634-.362-3.781 2.183-1.62 3.592-6.35 8.146-10.5 10.108-6.802 2.532-14.865 2.503-20.008-.574-2.04-1.227-4.647-3.319-5.793-4.649-4.514-5.237-7.695-13.41-8.096-20.81l-.187-3.48 10.83-1.739c5.957-.956 14.7-2.342 19.43-3.08 13.652-2.129 14.071-2.383 12.334-7.5-1.353-3.984-3.921-7.914-7.002-10.977C105.832 61.307 99.815 60.001 94.99 60zm-3.896 5.076c1.534-.03 3.06.215 4.513.766 3.8 1.44 7.13 6.226 7.389 10.617.189 3.195-.68 3.53-14.352 5.547-6.217.917-11.707 1.823-12.199 2.012-.493.189-1.044.105-1.225-.188-.545-.881.689-6.26 2.147-9.361 2.672-5.685 8.248-9.288 13.727-9.393z"
                  />
                </svg>
              </div>
              <div>
                <span className="text-sm font-medium">eSewa</span>
                <p className="text-xs text-stone-500">
                  {isSubscribed
                    ? "Active payment method · NPR"
                    : "Pay securely with eSewa"}
                </p>
              </div>
            </div>
            {isSubscribed && (
              <span className="text-[10px] font-mono uppercase tracking-wider text-emerald-500 bg-emerald-500/10 px-2 py-0.5 rounded-full font-semibold">
                Connected
              </span>
            )}
          </div>
          {isFree && upgradePlan && (
            <div className="flex items-start gap-3 bg-purple-500/5 border border-purple-500/20 rounded-lg px-4 py-3">
              <IconRocket
                size={16}
                className="text-purple-400 mt-0.5 shrink-0"
              />
              <div>
                <p className="text-xs text-purple-300/80">
                  You&apos;re on the <strong>Free Trial</strong>. Upgrade to{" "}
                  <strong>{upgradePlan.name}</strong> starting at{" "}
                  {upgradePlan.price}
                  {upgradePlan.period} — pay with eSewa in NPR.
                </p>
                <Button
                  variant="link"
                  size="sm"
                  className="p-0 h-auto text-purple-400 text-xs mt-1"
                  onClick={() => {
                    const url = new URL(window.location.href);
                    url.searchParams.set("tab", "plan");
                    window.history.pushState({}, "", url.toString());
                    window.dispatchEvent(new PopStateEvent("popstate"));
                    window.location.href = "/account?tab=plan";
                  }}
                >
                  View Plans <IconChevronRight size={12} />
                </Button>
              </div>
            </div>
          )}
        </div>
      </SectionCard>

      <SectionCard
        title="Billing History"
        description="Past payments and receipts"
        icon={IconChartBar}
      >
        <div className="flex flex-col gap-4">
          {lastPayment ? (
            <div className="flex flex-col gap-3">
              <div className="flex items-center justify-between bg-stone-100 border border-stone-300 rounded-lg px-4 py-3">
                <div className="flex items-center gap-3">
                  <div className="p-1.5 rounded-md bg-stone-200">
                    <IconCreditCard size={14} className="text-stone-400" />
                  </div>
                  <div>
                    <span className="text-sm font-medium">
                      {formatNpr(lastPayment.amount)}
                    </span>
                    <p className="text-[11px] text-stone-500">
                      {lastPayment.createdAt
                        ? formatDate(new Date(lastPayment.createdAt))
                        : "—"}{" "}
                      · {lastPayment.planId} plan
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {lastPayment.esewaRefId && (
                    <span className="text-[10px] font-mono text-stone-600 hidden md:inline">
                      Ref: {lastPayment.esewaRefId}
                    </span>
                  )}
                  <span
                    className={`text-[10px] font-mono uppercase tracking-wider px-2 py-0.5 rounded-full font-semibold ${
                      lastPayment.status === "completed"
                        ? "text-emerald-500 bg-emerald-500/10"
                        : lastPayment.status === "pending"
                          ? "text-amber-500 bg-amber-500/10"
                          : "text-red-400 bg-red-500/10"
                    }`}
                  >
                    {lastPayment.status}
                  </span>
                </div>
              </div>

              {lastPayment.periodStart && lastPayment.periodEnd && (
                <p className="text-[11px] text-stone-600 px-1">
                  Billing period:{" "}
                  {formatDate(new Date(lastPayment.periodStart))} –{" "}
                  {formatDate(new Date(lastPayment.periodEnd))}
                </p>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-8 gap-2">
              <IconChartBar size={28} className="text-stone-600" />
              <p className="text-sm text-stone-500">No billing history yet</p>
              <p className="text-xs text-stone-600 text-center max-w-sm">
                Invoices will appear here when you subscribe to a paid plan via
                eSewa.
              </p>
            </div>
          )}
        </div>
      </SectionCard>
    </div>
  );
}
