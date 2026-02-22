import {
  pgTable,
  text,
  boolean,
  timestamp,
  integer,
  index,
  unique,
  pgEnum,
} from "drizzle-orm/pg-core";

export const user = pgTable("user", {
  id: text("id").primaryKey(),
  name: text("name"),
  email: text("email").unique().notNull(),
  emailVerified: boolean("email_verified").default(false),
  image: text("image"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
  twoFactorEnabled: boolean("two_factor_enabled").default(false),
});

export const session = pgTable(
  "session",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    token: text("token").unique().notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("idx_session_token").on(table.token),
    index("idx_session_user_id").on(table.userId),
    index("idx_session_expires").on(table.expiresAt),
  ],
);

export const account = pgTable(
  "account",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    accountId: text("account_id").notNull(),
    providerId: text("provider_id").notNull(),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    accessTokenExpiresAt: timestamp("access_token_expires_at"),
    refreshTokenExpiresAt: timestamp("refresh_token_expires_at"),
    scope: text("scope"),
    idToken: text("id_token"),
    password: text("password"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("idx_account_user_id").on(table.userId),
    unique("account_provider_unique").on(table.providerId, table.accountId),
  ],
);

export const verification = pgTable(
  "verification",
  {
    id: text("id").primaryKey(),
    identifier: text("identifier").notNull(),
    value: text("value").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [index("idx_verification_identifier").on(table.identifier)],
);

export const twoFactor = pgTable(
  "two_factor",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    secret: text("secret"),
    backupCodes: text("backup_codes"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [index("idx_two_factor_user_id").on(table.userId)],
);

export const passkey = pgTable(
  "passkey",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    name: text("name"),
    publicKey: text("public_key").notNull(),
    credentialId: text("credential_id").notNull(),
    counter: integer("counter").notNull().default(0),
    deviceType: text("device_type"),
    backedUp: boolean("backed_up").default(false),
    transports: text("transports"),
    aaguid: text("aaguid"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
  },
  (table) => [
    index("idx_passkey_user_id").on(table.userId),
    index("idx_passkey_credential_id").on(table.credentialId),
  ],
);

export const paymentStatusEnum = pgEnum("payment_status", [
  "pending",
  "completed",
  "failed",
  "refunded",
  "expired",
]);

export const subscriptionStatusEnum = pgEnum("subscription_status", [
  "active",
  "expired",
  "cancelled",
  "past_due",
]);

export const payment = pgTable(
  "payment",
  {
    id: text("id").primaryKey(), // UUID
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    transactionUuid: text("transaction_uuid").unique().notNull(),
    productCode: text("product_code").notNull(),
    planId: text("plan_id").notNull(),
    amount: integer("amount").notNull(),
    taxAmount: integer("tax_amount").notNull().default(0),
    totalAmount: integer("total_amount").notNull(),
    status: paymentStatusEnum("status").notNull().default("pending"),
    esewaRefId: text("esewa_ref_id"),
    esewaResponseRaw: text("esewa_response_raw"),
    periodStart: timestamp("period_start"),
    periodEnd: timestamp("period_end"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("idx_payment_user_id").on(table.userId),
    index("idx_payment_transaction_uuid").on(table.transactionUuid),
    index("idx_payment_status").on(table.status),
  ],
);

export const subscription = pgTable(
  "subscription",
  {
    id: text("id").primaryKey(), // UUID
    userId: text("user_id")
      .notNull()
      .unique()
      .references(() => user.id, { onDelete: "cascade" }),
    planId: text("plan_id").notNull().default("free_trial"),
    status: subscriptionStatusEnum("status").notNull().default("active"),
    currentPaymentId: text("current_payment_id").references(() => payment.id),
    currentPeriodStart: timestamp("current_period_start")
      .notNull()
      .defaultNow(),
    currentPeriodEnd: timestamp("current_period_end").notNull(),
    autoRenew: boolean("auto_renew").notNull().default(false),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("idx_subscription_user_id").on(table.userId),
    index("idx_subscription_status").on(table.status),
    index("idx_subscription_period_end").on(table.currentPeriodEnd),
  ],
);


export const schema = {
  user,
  session,
  account,
  verification,
  twoFactor,
  passkey,
  payment,
  subscription,
};

export type User = typeof user.$inferSelect;
export type Session = typeof session.$inferSelect;
export type Account = typeof account.$inferSelect;
export type Verification = typeof verification.$inferSelect;
export type TwoFactor = typeof twoFactor.$inferSelect;
export type Passkey = typeof passkey.$inferSelect;
export type Payment = typeof payment.$inferSelect;
export type Subscription = typeof subscription.$inferSelect;
