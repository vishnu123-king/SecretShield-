import { drizzle as drizzlePg } from 'drizzle-orm/node-postgres';
import { drizzle as drizzlePglite } from 'drizzle-orm/pglite';
import { PGlite } from '@electric-sql/pglite';
import pkg from 'pg';
const { Pool } = pkg;
import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';
import * as schema from './schema.ts';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Global references for hot-reloads
declare global {
  var _drizzleDb: any;
  var _pgliteInstance: PGlite | undefined;
}

const dataDir = path.resolve(__dirname, '../../data/secretshield-pglite');

const CREATE_TABLES_SQL = `
CREATE TABLE IF NOT EXISTS organizations (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  role TEXT DEFAULT 'Standard',
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password TEXT NOT NULL,
  name TEXT,
  role TEXT DEFAULT 'ENGINEER',
  organization_id INTEGER REFERENCES organizations(id),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS repositories (
  id SERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  url TEXT,
  path TEXT NOT NULL,
  source TEXT NOT NULL,
  provider_name TEXT,
  provider_badge TEXT,
  default_branch TEXT DEFAULT 'main',
  last_scanned_at TIMESTAMP,
  risk_index INTEGER DEFAULT 0,
  status TEXT DEFAULT 'idle',
  total_findings INTEGER DEFAULT 0,
  organization_id INTEGER REFERENCES organizations(id),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scans (
  id SERIAL PRIMARY KEY,
  scan_id TEXT NOT NULL UNIQUE,
  repository_id INTEGER REFERENCES repositories(id) NOT NULL,
  repository_name TEXT NOT NULL,
  repository_url TEXT,
  provider TEXT,
  scan_mode TEXT NOT NULL,
  status TEXT NOT NULL,
  current_stage TEXT,
  duration_seconds DOUBLE PRECISION DEFAULT 0,
  total_findings INTEGER DEFAULT 0,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  currently_exposed_count INTEGER DEFAULT 0,
  historical_only_count INTEGER DEFAULT 0,
  risk_index INTEGER DEFAULT 0,
  raw_output JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
  id SERIAL PRIMARY KEY,
  finding_id TEXT NOT NULL,
  scan_id INTEGER REFERENCES scans(id) NOT NULL,
  repository_id INTEGER REFERENCES repositories(id) NOT NULL,
  repository_name TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  title TEXT NOT NULL,
  secret_type TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence DOUBLE PRECISION DEFAULT 0.8,
  score INTEGER DEFAULT 50,
  masked_secret TEXT NOT NULL,
  primary_file TEXT NOT NULL,
  primary_line INTEGER DEFAULT 1,
  status TEXT DEFAULT 'Open',
  is_currently_present BOOLEAN DEFAULT TRUE,
  first_seen TIMESTAMP,
  last_seen TIMESTAMP,
  total_occurrences INTEGER DEFAULT 1,
  remediation TEXT,
  risk_reasons JSONB,
  context JSONB,
  files JSONB,
  commits JSONB,
  branches JSONB,
  occurrences JSONB,
  ai_explanation TEXT,
  evidence_points JSONB,
  operational_risk TEXT,
  blast_radius JSONB,
  exposure_events JSONB,
  history_logs JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS fingerprint_idx ON findings(fingerprint, repository_id);

CREATE TABLE IF NOT EXISTS suppressions (
  id SERIAL PRIMARY KEY,
  finding_id INTEGER REFERENCES findings(id),
  fingerprint TEXT,
  rule_id TEXT,
  path_pattern TEXT,
  reason TEXT NOT NULL,
  expires_at TIMESTAMP,
  created_by TEXT,
  organization_id INTEGER REFERENCES organizations(id),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id SERIAL PRIMARY KEY,
  user_email TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  details TEXT,
  organization_id INTEGER REFERENCES organizations(id),
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS policies (
  id SERIAL PRIMARY KEY,
  organization_id INTEGER UNIQUE REFERENCES organizations(id),
  critical TEXT DEFAULT 'block',
  high TEXT DEFAULT 'block',
  medium TEXT DEFAULT 'warn',
  low TEXT DEFAULT 'inform',
  precommit_enforced BOOLEAN DEFAULT TRUE,
  diff_scan_enforced BOOLEAN DEFAULT TRUE,
  pr_checks_enforced BOOLEAN DEFAULT TRUE,
  ci_gate_enforced BOOLEAN DEFAULT TRUE,
  max_allowed_risk_score INTEGER DEFAULT 50,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);
`;

const useExternalPostgres = Boolean(
  process.env.DATABASE_URL &&
  !process.env.DATABASE_URL.includes('user:password@host') &&
  !process.env.DATABASE_URL.includes('localhost:5432/secretshield')
);

let pgliteInstance: PGlite | null = null;
let currentDb: any = null;

if (useExternalPostgres) {
  const isProd = process.env.NODE_ENV === 'production';
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: isProd && !process.env.DATABASE_URL?.includes('localhost') ? { rejectUnauthorized: false } : false,
    max: 10,
    connectionTimeoutMillis: 15000,
  });
  pool.on('error', (err) => {
    console.error('Unexpected error on idle SQL pool client:', err);
  });
  currentDb = drizzlePg(pool, { schema });
} else {
  // Use embedded PGlite (No Cloud SQL / external DB required!)
  if (!global._pgliteInstance) {
    fs.mkdirSync(path.dirname(dataDir), { recursive: true });
    global._pgliteInstance = new PGlite(dataDir);
  }
  pgliteInstance = global._pgliteInstance;
  currentDb = drizzlePglite(pgliteInstance, { schema });
}

export const db: any = currentDb;

export async function initDatabase() {
  try {
    if (!useExternalPostgres && pgliteInstance) {
      await pgliteInstance.waitReady;
      await pgliteInstance.exec(CREATE_TABLES_SQL);
      console.log('âœ“ SecretShield embedded database initialized successfully');

      // Check if default organization exists
      const existingOrgs = await pgliteInstance.query('SELECT id FROM organizations LIMIT 1;');
      if (existingOrgs.rows.length === 0) {
        console.log('Seeding initial organization, policy, and demo user...');
        const orgRes = await pgliteInstance.query(
          "INSERT INTO organizations (name, role) VALUES ('Default Organization', 'Enterprise') RETURNING id;"
        );
        const orgId = (orgRes.rows[0] as any).id;

        // Create default policy
        await pgliteInstance.query(
          `INSERT INTO policies (organization_id, critical, high, medium, low, precommit_enforced, diff_scan_enforced, pr_checks_enforced, ci_gate_enforced, max_allowed_risk_score)
           VALUES ($1, 'block', 'block', 'warn', 'inform', true, true, true, true, 50);`,
          [orgId]
        );

        // Create demo user: demo@secretshield.io / Password123!
        const hashedPassword = await bcrypt.hash('Password123!', 10);
        await pgliteInstance.query(
          `INSERT INTO users (email, password, name, role, organization_id)
           VALUES ('demo@secretshield.io', $1, 'Security Analyst', 'ADMIN', $2);`,
          [hashedPassword, orgId]
        );

        console.log('âœ“ Default demo user (demo@secretshield.io) seeded');

        // Seed initial sample repository and findings
        await seedSampleData(pgliteInstance, orgId);
      }
    }
  } catch (err) {
    console.error('Failed to initialize database:', err);
  }
}

async function seedSampleData(client: PGlite, orgId: number) {
  try {
    const fixtureDir = path.resolve(__dirname, '../../tests/fixtures/sample-repository');
    
    // Insert Sample Repo
    const repoRes = await client.query(
      `INSERT INTO repositories (name, url, path, source, provider_name, provider_badge, default_branch, risk_index, status, total_findings, organization_id, last_scanned_at)
       VALUES ('payments-gateway', 'https://github.com/acme-corp/payments-gateway.git', $1, 'github', 'GitHub', 'cyan', 'main', 88, 'idle', 4, $2, NOW())
       RETURNING id;`,
      [fixtureDir, orgId]
    );
    const repoId = (repoRes.rows[0] as any).id;

    // Insert Scan
    const scanId = `scan-init-${Date.now()}`;
    const scanRes = await client.query(
      `INSERT INTO scans (scan_id, repository_id, repository_name, repository_url, provider, scan_mode, status, current_stage, duration_seconds, total_findings, critical_count, high_count, medium_count, low_count, currently_exposed_count, historical_only_count, risk_index)
       VALUES ($1, $2, 'payments-gateway', 'https://github.com/acme-corp/payments-gateway.git', 'GitHub', 'deep', 'completed', 'completed', 1.84, 4, 2, 1, 1, 0, 2, 2, 88)
       RETURNING id;`,
      [scanId, repoId]
    );
    const scanRecordId = (scanRes.rows[0] as any).id;

    // Insert Seed Findings
    const sampleFindings = [
      {
        findingId: 'SEC-1001',
        title: 'Live GitHub Personal Access Token in Working Tree',
        secretType: 'github_token',
        ruleId: 'github-pat',
        ruleName: 'GitHub Personal Access Token',
        severity: 'CRITICAL',
        confidence: 0.98,
        score: 95,
        maskedSecret: 'ghp_****************9999',
        primaryFile: 'services/github_sync.py',
        primaryLine: 4,
        isCurrentlyPresent: true,
        remediation: '1. Immediately revoke token in GitHub Settings > Developer Settings.\n2. Invalidate upstream permissions.\n3. Reissue token and configure in GitHub Actions Secrets.',
        aiExplanation: 'CRITICAL THREAT: Active high-privilege GitHub Personal Access Token committed in services/github_sync.py. Key is currently present in HEAD and exposed to clone operations.',
        operationalRisk: 'HIGH_LIVE_CREDENTIAL_PROBABILITY',
        evidencePoints: JSON.stringify([
          'Matches verifiable signature pattern for GitHub Personal Access Token',
          'High mathematical entropy confidence (98%)',
          'Committed directly in source code file',
          'Currently present in repository HEAD'
        ]),
        riskReasons: JSON.stringify([
          { delta: '+45', factor: 'Critical authentication credential pattern', impact: 'positive' },
          { delta: '+25', factor: 'Present in current working tree HEAD', impact: 'positive' },
          { delta: '+15', factor: 'Source code in services/ directory', impact: 'positive' }
        ]),
        blastRadius: JSON.stringify({
          scope: 'Source Code & Version Control',
          containment_priority: 'P0_IMMEDIATE_REVOCATION',
          recommended_actions: [
            'Revoke personal access token in GitHub Developer Settings',
            'Review recent repository activity logs for unauthorized pushes or downloads',
            'Migrate secret to GitHub Secrets Manager'
          ]
        }),
        exposureEvents: JSON.stringify([
          { date: new Date().toISOString(), title: 'Credential Introduced', description: 'Committed to services/github_sync.py', type: 'INTRODUCED' },
          { date: 'Present', title: 'Active Exposure in HEAD', description: 'Currently readable in latest codebase', type: 'ACTIVE_EXPOSURE' }
        ]),
        files: JSON.stringify(['services/github_sync.py']),
        commits: JSON.stringify(['547c67859a']),
        branches: JSON.stringify(['main']),
        fingerprint: 'sha256:github_pat_payments_gateway_01'
      },
      {
        findingId: 'SEC-1002',
        title: 'Production PostgreSQL Database Connection String',
        secretType: 'database_uri',
        ruleId: 'postgres-uri',
        ruleName: 'PostgreSQL Connection URI',
        severity: 'CRITICAL',
        confidence: 0.96,
        score: 90,
        maskedSecret: 'postgres://appuser:********@db.prod.internal:5432/payments_db',
        primaryFile: 'config.py',
        primaryLine: 29,
        isCurrentlyPresent: false,
        remediation: '1. Change database password for user appuser on payments_db.\n2. Terminate all active database connections.\n3. Update application environment variables via Doppler or AWS Secrets Manager.',
        aiExplanation: 'HISTORICAL EXPOSURE: Full PostgreSQL production connection string with plaintext credentials was committed in git history. Even though removed from current HEAD, it remains extractable via git log / checkout.',
        operationalRisk: 'HIGH_DATABASE_TAKEOVER_RISK',
        evidencePoints: JSON.stringify([
          'Contains plaintext database username and password',
          'Targets internal production database host db.prod.internal',
          'Historical git commit presence across commit history'
        ]),
        riskReasons: JSON.stringify([
          { delta: '+45', factor: 'Production database credentials exposed', impact: 'positive' },
          { delta: '+15', factor: 'Present in git history commits', impact: 'positive' },
          { delta: '-10', factor: 'Removed from latest HEAD', impact: 'negative' }
        ]),
        blastRadius: JSON.stringify({
          scope: 'Production Database & Payment Records',
          containment_priority: 'P0_ROTATE_DATABASE_PASSWORD',
          recommended_actions: [
            'Rotate database password for appuser immediately',
            'Verify audit logs for suspicious SQL queries',
            'Purge commit from git history using git filter-repo'
          ]
        }),
        exposureEvents: JSON.stringify([
          { date: new Date(Date.now() - 86400000 * 2).toISOString(), title: 'Committed to config.py', description: 'feat: initial payment service setup', type: 'INTRODUCED' },
          { date: new Date(Date.now() - 86400000).toISOString(), title: 'Removed from config.py', description: 'fix(security): remove credentials', type: 'REMOVED_FROM_HEAD' }
        ]),
        files: JSON.stringify(['config.py']),
        commits: JSON.stringify(['a1b2c3d4e5']),
        branches: JSON.stringify(['main']),
        fingerprint: 'sha256:pg_uri_payments_gateway_02'
      },
      {
        findingId: 'SEC-1003',
        title: 'Stripe Live Secret Key in Environment File',
        secretType: 'stripe_secret',
        ruleId: 'stripe-secret-key',
        ruleName: 'Stripe Live API Key',
        severity: 'HIGH',
        confidence: 0.95,
        score: 85,
        maskedSecret: process.env.STRIPE_SECRET_KEY,
        primaryFile: '.env.production',
        primaryLine: 2,
        isCurrentlyPresent: false,
        remediation: '1. Roll the secret key in Stripe Dashboard > Developers > API Keys.\n2. Review Stripe balance and recent charge logs for unauthorized activity.',
        aiExplanation: 'HIGH THREAT: Stripe live secret key discovered in historical .env.production file. Can be exploited to trigger refunds, access customer PII, or charge cards.',
        operationalRisk: 'FINANCIAL_TRANSACTION_EXPOSURE',
        evidencePoints: JSON.stringify([
          'Matches live Stripe API secret format (sk_live_*)',
          'High entropy API token',
          'Present in historical commit'
        ]),
        riskReasons: JSON.stringify([
          { delta: '+40', factor: 'Stripe live financial gateway secret', impact: 'positive' },
          { delta: '+15', factor: 'Historical commit exposure', impact: 'positive' }
        ]),
        blastRadius: JSON.stringify({
          scope: 'Payment Processing & Customer Transactions',
          containment_priority: 'P1_KEY_ROTATION',
          recommended_actions: [
            'Roll Stripe API secret key in Stripe Dashboard',
            'Inspect webhook endpoints and recent charges'
          ]
        }),
        exposureEvents: JSON.stringify([
          { date: new Date(Date.now() - 86400000 * 2).toISOString(), title: 'Committed to .env.production', description: 'feat: initial payment service setup', type: 'INTRODUCED' }
        ]),
        files: JSON.stringify(['.env.production']),
        commits: JSON.stringify(['a1b2c3d4e5']),
        branches: JSON.stringify(['main']),
        fingerprint: 'sha256:stripe_sk_payments_gateway_03'
      },
      {
        findingId: 'SEC-1004',
        title: 'Slack Bot Webhook OAuth Token',
        secretType: 'slack_token',
        ruleId: 'slack-bot-token',
        ruleName: 'Slack Bot User OAuth Token',
        severity: 'MEDIUM',
        confidence: 0.91,
        score: 65,
        maskedSecret: process.env.SLACK_BOT_TOKEN,
        primaryFile: '.env.production',
        primaryLine: 3,
        isCurrentlyPresent: false,
        remediation: '1. Revoke Slack Bot token in api.slack.com apps portal.\n2. Reissue token and restrict OAuth scopes.',
        aiExplanation: 'MEDIUM RISK: Slack Bot OAuth token allows reading and posting messages in configured Slack channels.',
        operationalRisk: 'INTERNAL_COMMUNICATIONS_INTERCEPTION',
        evidencePoints: JSON.stringify([
          'Matches standard Slack bot format (xoxb-*)',
          'Historical file commit'
        ]),
        riskReasons: JSON.stringify([
          { delta: '+30', factor: 'Slack bot token format match', impact: 'positive' },
          { delta: '+10', factor: 'Committed in .env.production', impact: 'positive' }
        ]),
        blastRadius: JSON.stringify({
          scope: 'Internal Team Chat & Alerts',
          containment_priority: 'P2_REVOKE_SLACK_BOT',
          recommended_actions: [
            'Revoke bot token on Slack API portal',
            'Rotate incoming webhook URLs'
          ]
        }),
        exposureEvents: JSON.stringify([
          { date: new Date(Date.now() - 86400000 * 2).toISOString(), title: 'Committed to .env.production', description: 'feat: initial payment service setup', type: 'INTRODUCED' }
        ]),
        files: JSON.stringify(['.env.production']),
        commits: JSON.stringify(['a1b2c3d4e5']),
        branches: JSON.stringify(['main']),
        fingerprint: 'sha256:slack_bot_payments_gateway_04'
      }
    ];

    for (const f of sampleFindings) {
      await client.query(
        `INSERT INTO findings (
          finding_id, scan_id, repository_id, repository_name, fingerprint, title, secret_type,
          rule_id, rule_name, severity, confidence, score, masked_secret, primary_file, primary_line,
          status, is_currently_present, first_seen, last_seen, total_occurrences, remediation,
          ai_explanation, operational_risk, evidence_points, risk_reasons, blast_radius, exposure_events,
          files, commits, branches
        ) VALUES (
          $1, $2, $3, 'payments-gateway', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14,
          'Open', $15, NOW(), NOW(), 1, $16, $17, $18, $19::jsonb, $20::jsonb, $21::jsonb, $22::jsonb,
          $23::jsonb, $24::jsonb, $25::jsonb
        ) ON CONFLICT (fingerprint, repository_id) DO NOTHING;`,
        [
          f.findingId, scanRecordId, repoId, f.fingerprint, f.title, f.secretType,
          f.ruleId, f.ruleName, f.severity, f.confidence, f.score, f.maskedSecret, f.primaryFile, f.primaryLine,
          f.isCurrentlyPresent, f.remediation, f.aiExplanation, f.operationalRisk,
          f.evidencePoints, f.riskReasons, f.blastRadius, f.exposureEvents,
          f.files, f.commits, f.branches
        ]
      );
    }

    // Insert sample audit log
    await client.query(
      `INSERT INTO audit_logs (user_email, action, target_type, target_id, details, organization_id)
       VALUES ('demo@secretshield.io', 'SYSTEM_INITIALIZATION', 'SYSTEM', '1', 'Initial database tables and sample fixture repository initialized', $1);`,
      [orgId]
    );

    console.log('âœ“ Sample repository, scan, and security findings seeded');
  } catch (err) {
    console.error('Failed to seed sample repository data:', err);
  }
}


