import { pgTable, serial, text, timestamp, integer, boolean, jsonb, doublePrecision, uniqueIndex } from 'drizzle-orm/pg-core';
import { relations } from 'drizzle-orm';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  email: text('email').notNull().unique(),
  password: text('password').notNull(),
  name: text('name'),
  role: text('role').default('ENGINEER'), // ADMIN, ENGINEER, ANALYST
  organizationId: integer('organization_id').references(() => organizations.id),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

export const organizations = pgTable('organizations', {
  id: serial('id').primaryKey(),
  name: text('name').notNull(),
  plan: text('role').default('Standard'),
  createdAt: timestamp('created_at').defaultNow(),
});

export const repositories = pgTable('repositories', {
  id: serial('id').primaryKey(),
  name: text('name').notNull(),
  url: text('url'),
  path: text('path').notNull(),
  source: text('source').notNull(), // 'github', 'gitlab', etc.
  providerName: text('provider_name'),
  providerBadge: text('provider_badge'),
  defaultBranch: text('default_branch').default('main'),
  lastScannedAt: timestamp('last_scanned_at'),
  riskIndex: integer('risk_index').default(0),
  status: text('status').default('idle'), // 'idle', 'scanning', 'error'
  totalFindings: integer('total_findings').default(0),
  organizationId: integer('organization_id').references(() => organizations.id),
  createdAt: timestamp('created_at').defaultNow(),
});

export const scans = pgTable('scans', {
  id: serial('id').primaryKey(),
  scanExternalId: text('scan_id').notNull().unique(), // e.g. scan-12345
  repositoryId: integer('repository_id').references(() => repositories.id).notNull(),
  repositoryName: text('repository_name').notNull(),
  repositoryUrl: text('repository_url'),
  provider: text('provider'),
  scanMode: text('scan_mode').notNull(), // 'quick', 'deep', 'full', 'diff'
  status: text('status').notNull(), // 'running', 'completed', 'failed'
  currentStage: text('current_stage'),
  durationSeconds: doublePrecision('duration_seconds').default(0),
  totalFindings: integer('total_findings').default(0),
  criticalCount: integer('critical_count').default(0),
  highCount: integer('high_count').default(0),
  mediumCount: integer('medium_count').default(0),
  lowCount: integer('low_count').default(0),
  currentlyExposedCount: integer('currently_exposed_count').default(0),
  historicalOnlyCount: integer('historical_only_count').default(0),
  riskIndex: integer('risk_index').default(0),
  rawOutput: jsonb('raw_output'),
  createdAt: timestamp('created_at').defaultNow(),
});

export const findings = pgTable('findings', {
  id: serial('id').primaryKey(),
  findingExternalId: text('finding_id').notNull(), // e.g. SEC-0001
  scanId: integer('scan_id').references(() => scans.id).notNull(),
  repositoryId: integer('repository_id').references(() => repositories.id).notNull(),
  repositoryName: text('repository_name').notNull(),
  fingerprint: text('fingerprint').notNull(),
  title: text('title').notNull(),
  secretType: text('secret_type').notNull(),
  ruleId: text('rule_id').notNull(),
  ruleName: text('rule_name').notNull(),
  severity: text('severity').notNull(), // CRITICAL, HIGH, MEDIUM, LOW, INFO
  confidence: doublePrecision('confidence').default(0.8),
  score: integer('score').default(50),
  maskedSecret: text('masked_secret').notNull(),
  primaryFile: text('primary_file').notNull(),
  primaryLine: integer('primary_line').default(1),
  status: text('status').default('Open'), // 'Open', 'Investigating', etc.
  isCurrentlyPresent: boolean('is_currently_present').default(true),
  firstSeen: timestamp('first_seen'),
  lastSeen: timestamp('last_seen'),
  totalOccurrences: integer('total_occurrences').default(1),
  remediation: text('remediation'),
  riskReasons: jsonb('risk_reasons'),
  context: jsonb('context'),
  files: jsonb('files'), // Array of strings
  commits: jsonb('commits'), // Array of strings
  branches: jsonb('branches'), // Array of strings
  occurrences: jsonb('occurrences'),
  aiExplanation: text('ai_explanation'),
  evidencePoints: jsonb('evidence_points'),
  operationalRisk: text('operational_risk'),
  blastRadius: jsonb('blast_radius'),
  exposureEvents: jsonb('exposure_events'),
  historyLogs: jsonb('history_logs'),
  createdAt: timestamp('created_at').defaultNow(),
}, (table) => {
  return {
    fingerprintIdx: uniqueIndex('fingerprint_idx').on(table.fingerprint, table.repositoryId),
  };
});

export const suppressions = pgTable('suppressions', {
  id: serial('id').primaryKey(),
  findingId: integer('finding_id').references(() => findings.id),
  fingerprint: text('fingerprint'),
  ruleId: text('rule_id'),
  pathPattern: text('path_pattern'),
  reason: text('reason').notNull(),
  expiresAt: timestamp('expires_at'),
  createdBy: text('created_by'), // User UID
  organizationId: integer('organization_id').references(() => organizations.id),
  createdAt: timestamp('created_at').defaultNow(),
});

export const auditLogs = pgTable('audit_logs', {
  id: serial('id').primaryKey(),
  userEmail: text('user_email').notNull(),
  action: text('action').notNull(),
  targetType: text('target_type'),
  targetId: text('target_id'),
  details: text('details'),
  organizationId: integer('organization_id').references(() => organizations.id),
  createdAt: timestamp('created_at').defaultNow(),
});

export const policies = pgTable('policies', {
  id: serial('id').primaryKey(),
  organizationId: integer('organization_id').references(() => organizations.id).unique(),
  critical: text('critical').default('block'),
  high: text('high').default('block'),
  medium: text('medium').default('warn'),
  low: text('low').default('inform'),
  precommitEnforced: boolean('precommit_enforced').default(true),
  diffScanEnforced: boolean('diff_scan_enforced').default(true),
  prChecksEnforced: boolean('pr_checks_enforced').default(true),
  ciGateEnforced: boolean('ci_gate_enforced').default(true),
  maxAllowedRiskScore: integer('max_allowed_risk_score').default(50),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

// Relations
export const usersRelations = relations(users, ({ one }) => ({
  organization: one(organizations, {
    fields: [users.organizationId],
    references: [organizations.id],
  }),
}));

export const organizationsRelations = relations(organizations, ({ many }) => ({
  users: many(users),
  repositories: many(repositories),
  scans: many(scans),
  findings: many(findings),
  suppressions: many(suppressions),
  auditLogs: many(auditLogs),
  policy: many(policies),
}));

export const repositoriesRelations = relations(repositories, ({ one, many }) => ({
  organization: one(organizations, {
    fields: [repositories.organizationId],
    references: [organizations.id],
  }),
  scans: many(scans),
  findings: many(findings),
}));

export const scansRelations = relations(scans, ({ one, many }) => ({
  repository: one(repositories, {
    fields: [scans.repositoryId],
    references: [repositories.id],
  }),
  findings: many(findings),
}));

export const findingsRelations = relations(findings, ({ one }) => ({
  scan: one(scans, {
    fields: [findings.scanId],
    references: [scans.id],
  }),
  repository: one(repositories, {
    fields: [findings.repositoryId],
    references: [repositories.id],
  }),
}));
