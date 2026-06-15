export type AuditCategory =
  | "credential-file"
  | "private-key"
  | "bundled-secret"
  | "scm-leakage"
  | "ci-config"
  | "iac-secret"
  | "source-map"
  | "build-artifact"
  | "editor-os-junk"
  | "data-dump"
  | "internal-leak"
  | "lifecycle-risk"
  | "structural";

export type AuditSeverity = 1 | 2 | 3 | 4 | 5;

export interface FilenameRule {
  readonly id: string;
  readonly re: RegExp;
  readonly category: AuditCategory;
  readonly severity: AuditSeverity;
  readonly title: string;
  readonly recommendation: string;
  readonly exempt?: RegExp;
  readonly gateContent?: RegExp;
}

export interface ContentRule {
  readonly id: string;
  readonly re: RegExp;
  readonly category: AuditCategory;
  readonly severity: AuditSeverity;
  readonly title: string;
  readonly recommendation: string;
  readonly allow?: RegExp;
}

export const FILENAME_RULES: readonly FilenameRule[] = [
  {
    id: "env-file",
    re: /(^|\/)\.env(\.[^/]+)?$/iu,
    exempt: /\.env\.(example|sample|template|dist|defaults?)$/iu,
    category: "credential-file",
    severity: 4,
    title: "Environment file bundled in publish payload",
    recommendation: "Exclude .env files and rotate any exposed secrets."
  },
  {
    id: "npmrc",
    re: /(^|\/)\.npmrc$/iu,
    category: "credential-file",
    severity: 5,
    title: ".npmrc bundled in publish payload",
    recommendation: "Remove .npmrc and revoke any registry token it contained."
  },
  {
    id: "pypirc",
    re: /(^|\/)\.pypirc$/iu,
    category: "credential-file",
    severity: 5,
    title: ".pypirc bundled in publish payload",
    recommendation: "Remove .pypirc and revoke any PyPI token it contained."
  },
  {
    id: "yarnrc",
    re: /(^|\/)\.yarnrc(\.yml)?$/iu,
    category: "credential-file",
    severity: 4,
    title: "Yarn registry configuration bundled in publish payload",
    recommendation: "Exclude Yarn registry config and verify it holds no credentials."
  },
  {
    id: "netrc",
    re: /(^|\/)_?\.?netrc$/iu,
    category: "credential-file",
    severity: 5,
    title: ".netrc bundled in publish payload",
    recommendation: "Remove .netrc and rotate the machine credentials it stored."
  },
  {
    id: "git-credentials",
    re: /(^|\/)\.git-credentials$/iu,
    category: "credential-file",
    severity: 5,
    title: ".git-credentials bundled in publish payload",
    recommendation: "Remove the file and rotate the git access token it stored."
  },
  {
    id: "aws-credentials",
    re: /(^|\/)\.aws\/(credentials|config)$/iu,
    category: "credential-file",
    severity: 5,
    title: "AWS credentials bundled in publish payload",
    recommendation: "Remove the credentials file and rotate the access key."
  },
  {
    id: "gcloud-sa",
    re: /(application_default_credentials|service[_-]?account[^/]*)\.json$/iu,
    gateContent: /"type"\s*:\s*"service_account"|"private_key"/u,
    category: "credential-file",
    severity: 5,
    title: "Google service-account key bundled in publish payload",
    recommendation: "Remove the key file and rotate the service account."
  },
  {
    id: "kube-config",
    re: /(^|\/)(\.kube\/config|kubeconfig)$/iu,
    gateContent: /client-key-data:|token:/u,
    category: "credential-file",
    severity: 5,
    title: "Kubernetes config bundled in publish payload",
    recommendation: "Remove the kubeconfig and rotate the cluster credentials."
  },
  {
    id: "docker-config",
    re: /(^|\/)\.docker\/config\.json$/iu,
    gateContent: /"auths"/u,
    category: "credential-file",
    severity: 5,
    title: "Docker registry credentials bundled in publish payload",
    recommendation: "Remove the file and rotate the registry credentials."
  },
  {
    id: "cargo-credentials",
    re: /(^|\/)\.cargo\/credentials(\.toml)?$/iu,
    category: "credential-file",
    severity: 5,
    title: "Cargo registry credentials bundled in publish payload",
    recommendation: "Remove the file and revoke the crates.io token."
  },
  {
    id: "htpasswd",
    re: /(^|\/)\.htpasswd$/iu,
    category: "credential-file",
    severity: 4,
    title: ".htpasswd bundled in publish payload",
    recommendation: "Remove the file; the password hashes are a cracking target."
  },
  {
    id: "ssh-key",
    re: /(^|\/)id_(rsa|ed25519|ecdsa|dsa)$/iu,
    category: "private-key",
    severity: 5,
    title: "SSH private key bundled in publish payload",
    recommendation: "Remove the key file and rotate the key."
  },
  {
    id: "ssh-pubkey",
    re: /(^|\/)id_(rsa|ed25519|ecdsa|dsa)\.pub$/iu,
    category: "credential-file",
    severity: 2,
    title: "SSH public key bundled in publish payload",
    recommendation: "Public keys are not secret, but were likely included by mistake."
  },
  {
    id: "key-bundle",
    re: /\.(p12|pfx|keystore|jks)$/iu,
    category: "private-key",
    severity: 5,
    title: "Key/certificate bundle in publish payload",
    recommendation: "Remove the keystore and rotate any private key it holds."
  },
  {
    id: "har-file",
    re: /\.har$/iu,
    category: "credential-file",
    severity: 4,
    title: "HTTP archive (.har) bundled in publish payload",
    recommendation: "HAR files routinely contain Authorization headers and cookies — remove it."
  },
  {
    id: "git-dir",
    re: /(^|\/)\.git\//iu,
    category: "scm-leakage",
    severity: 4,
    title: "Git history bundled in publish payload",
    recommendation: "Exclude .git — full history (including deleted secrets) is recoverable."
  },
  {
    id: "vcs-other",
    re: /(^|\/)\.(svn|hg|bzr)\//iu,
    category: "scm-leakage",
    severity: 3,
    title: "Version-control metadata bundled in publish payload",
    recommendation: "Exclude version-control directories from the package."
  },
  {
    id: "tfstate",
    re: /\.tfstate(\.backup)?$/iu,
    category: "iac-secret",
    severity: 5,
    title: "Terraform state bundled in publish payload",
    recommendation: "Remove it — tfstate stores resource secrets (passwords, keys) in plaintext."
  },
  {
    id: "terraform-dir",
    re: /(^|\/)\.terraform\//iu,
    category: "iac-secret",
    severity: 3,
    title: "Terraform working directory bundled in publish payload",
    recommendation: "Exclude .terraform from the package."
  },
  {
    id: "ci-config",
    re: /(^|\/)(\.github\/workflows\/[^/]+\.ya?ml|\.gitlab-ci\.yml|\.circleci\/config\.yml|Jenkinsfile|azure-pipelines\.yml|\.travis\.yml|bitbucket-pipelines\.yml|\.drone\.yml)$/iu,
    category: "ci-config",
    severity: 3,
    title: "CI configuration bundled in publish payload",
    recommendation: "CI configs are rarely meant to ship and can carry inline tokens — exclude them."
  },
  {
    id: "source-map",
    re: /\.(js|mjs|cjs|css)\.map$/iu,
    category: "source-map",
    severity: 3,
    title: "Source map bundled in publish payload",
    recommendation: "Source maps can reconstruct your original source — exclude them unless intended."
  },
  {
    id: "node-modules",
    re: /(^|\/)node_modules\//iu,
    category: "build-artifact",
    severity: 2,
    title: "node_modules bundled in publish payload",
    recommendation: "Exclude node_modules unless declared in bundledDependencies."
  },
  {
    id: "pycache",
    re: /(^|\/)(__pycache__\/|[^/]+\.py[co])$/iu,
    category: "build-artifact",
    severity: 1,
    title: "Python bytecode bundled in publish payload",
    recommendation: "Exclude __pycache__ and compiled bytecode."
  },
  {
    id: "coverage",
    re: /(^|\/)(coverage|\.nyc_output)\/|\.lcov$/iu,
    category: "build-artifact",
    severity: 2,
    title: "Coverage output bundled in publish payload",
    recommendation: "Exclude coverage reports — they leak local paths and test internals."
  },
  {
    id: "memory-dump",
    re: /\.(heapsnapshot|cpuprofile|dmp)$|(^|\/)core(\.[0-9]+)?$/iu,
    category: "build-artifact",
    severity: 4,
    title: "Memory/heap dump bundled in publish payload",
    recommendation: "Remove it — dumps can contain live secrets from process memory."
  },
  {
    id: "log-file",
    re: /(^|\/)(npm-debug\.log|yarn-error\.log|\.pnpm-debug\.log)$|\.log$/iu,
    category: "build-artifact",
    severity: 2,
    title: "Log file bundled in publish payload",
    recommendation: "Exclude logs — they often contain tokens and environment dumps."
  },
  {
    id: "ds-store",
    re: /(^|\/)\.DS_Store$/iu,
    category: "editor-os-junk",
    severity: 2,
    title: ".DS_Store bundled in publish payload",
    recommendation: "Exclude .DS_Store — it leaks the full directory listing."
  },
  {
    id: "os-junk",
    re: /(^|\/)(Thumbs\.db|desktop\.ini)$/iu,
    category: "editor-os-junk",
    severity: 1,
    title: "OS metadata bundled in publish payload",
    recommendation: "Exclude OS metadata files."
  },
  {
    id: "editor-dir",
    re: /(^|\/)\.(vscode|idea)\//iu,
    category: "editor-os-junk",
    severity: 2,
    title: "Editor configuration bundled in publish payload",
    recommendation: "Exclude editor dirs — .idea can hold data-source passwords."
  },
  {
    id: "editor-swap",
    re: /(\.sw[op]|~|\.bak|\.orig)$/iu,
    category: "editor-os-junk",
    severity: 2,
    title: "Editor/backup file bundled in publish payload",
    recommendation: "Exclude swap/backup files — they can hold unsaved secret edits."
  },
  {
    id: "sql-dump",
    re: /\.(sql|sql\.gz|dump)$/iu,
    category: "data-dump",
    severity: 3,
    title: "Database dump bundled in publish payload",
    recommendation: "Exclude DB dumps — they may contain PII and credentials."
  },
  {
    id: "sqlite-db",
    re: /\.(sqlite|sqlite3|db|rdb)$/iu,
    category: "data-dump",
    severity: 3,
    title: "Database file bundled in publish payload",
    recommendation: "Exclude database files — they may contain live sessions and tokens."
  },
  {
    id: "pcap",
    re: /\.pcap(ng)?$/iu,
    category: "data-dump",
    severity: 4,
    title: "Network capture bundled in publish payload",
    recommendation: "Remove it — captures expose auth headers and cookies in cleartext."
  }
];

export const CONTENT_RULES: readonly ContentRule[] = [
  {
    id: "pem-private-key",
    re: /-----BEGIN ((?:OPENSSH |RSA |DSA |EC |ENCRYPTED |PGP )?PRIVATE KEY)-----/u,
    category: "private-key",
    severity: 5,
    title: "Private-key block embedded in a published file",
    recommendation: "Treat the key as compromised, rotate it, and remove the file."
  },
  {
    id: "age-secret-key",
    re: /AGE-SECRET-KEY-1[0-9A-Z]{50,}/u,
    category: "private-key",
    severity: 5,
    title: "age secret key embedded in a published file",
    recommendation: "Rotate the age key and remove it from the payload."
  },
  {
    id: "aws-secret-key",
    re: /aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}/iu,
    category: "bundled-secret",
    severity: 5,
    title: "AWS secret access key embedded in a published file",
    recommendation: "Rotate the AWS access key and remove the secret."
  },
  {
    id: "aws-access-key-id",
    re: /\b(?:AKIA|ASIA|AROA|AGPA)[0-9A-Z]{16}\b/u,
    category: "bundled-secret",
    severity: 4,
    title: "AWS access key ID embedded in a published file",
    recommendation: "Rotate the AWS access key and remove the credential."
  },
  {
    id: "github-token",
    re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{82}\b/u,
    category: "bundled-secret",
    severity: 5,
    title: "GitHub token embedded in a published file",
    recommendation: "Revoke the token and remove it from the payload."
  },
  {
    id: "gitlab-token",
    re: /\b(?:glpat|gldt|glrt|glsoat)-[A-Za-z0-9_-]{20,}\b/u,
    category: "bundled-secret",
    severity: 5,
    title: "GitLab token embedded in a published file",
    recommendation: "Revoke the GitLab token and remove it from the payload."
  },
  {
    id: "slack-token",
    re: /\bxox[abpr]-[0-9]+-[0-9]+(?:-[0-9]+)?-[A-Za-z0-9]{10,}\b/u,
    category: "bundled-secret",
    severity: 5,
    title: "Slack token embedded in a published file",
    recommendation: "Revoke the Slack token and remove it from the payload."
  },
  {
    id: "slack-webhook",
    re: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]+/u,
    category: "bundled-secret",
    severity: 3,
    title: "Slack webhook URL embedded in a published file",
    recommendation: "Rotate the webhook and remove the URL from the payload."
  },
  {
    id: "stripe-key",
    re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{24,}\b/u,
    category: "bundled-secret",
    severity: 5,
    title: "Stripe API key embedded in a published file",
    recommendation: "Roll the Stripe key and remove it from the payload."
  },
  {
    id: "google-api-key",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/u,
    category: "bundled-secret",
    severity: 4,
    title: "Google API key embedded in a published file",
    recommendation: "Rotate the Google API key and remove it from the payload."
  },
  {
    id: "sendgrid-key",
    re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/u,
    category: "bundled-secret",
    severity: 5,
    title: "SendGrid API key embedded in a published file",
    recommendation: "Revoke the SendGrid key and remove it from the payload."
  },
  {
    id: "twilio-key",
    re: /\bSK[0-9a-fA-F]{32}\b/u,
    category: "bundled-secret",
    severity: 4,
    title: "Twilio API key embedded in a published file",
    recommendation: "Rotate the Twilio key and remove it from the payload."
  },
  {
    id: "npm-auth-token",
    re: /_authToken\s*=\s*[A-Za-z0-9_=+/-]{20,}|\bNODE_AUTH_TOKEN\s*=\s*[A-Za-z0-9_=+/-]{20,}|\bnpm_[A-Za-z0-9]{36}\b/u,
    category: "bundled-secret",
    severity: 4,
    title: "npm registry token embedded in a published file",
    recommendation: "Revoke the registry token and exclude the file."
  },
  {
    id: "db-connection-string",
    re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:@\s/]+:[^@\s/]+@[^/\s]+/u,
    allow: /:\/\/[^:@/]+:(password|pass|user|example|changeme|xxx+|\*+)@|@(localhost|127\.0\.0\.1|example\.|host\b)/iu,
    category: "bundled-secret",
    severity: 4,
    title: "Database connection string with password embedded in a published file",
    recommendation: "Move the credential to configuration and remove it from the payload."
  },
  {
    id: "jwt",
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/u,
    category: "bundled-secret",
    severity: 3,
    title: "JWT embedded in a published file",
    recommendation: "Confirm the token is not a live credential, then remove it."
  },
  {
    id: "ansible-vault",
    re: /\$ANSIBLE_VAULT;[0-9.]+;AES256/u,
    category: "iac-secret",
    severity: 3,
    title: "Ansible Vault ciphertext embedded in a published file",
    recommendation: "Exclude vault files; ensure the vault password is not shipped alongside."
  }
];

export const RISKY_SCRIPT_NAMES: readonly string[] = [
  "preinstall",
  "install",
  "postinstall",
  "preprepare",
  "prepare",
  "postprepare",
  "prepublish",
  "prepublishOnly",
  "prepack",
  "postpack",
  "preuninstall",
  "uninstall"
];

// Best-effort heuristic on the LOCAL audit only; a public regex is evadable, so
// the authoritative verdict is the behavioral scanner. Covers pipe-to-shell, eval,
// node -e, python -c, base64 -d, curl|sh, AND download-then-execute where the fetch
// is chained (&& / ;) to a shell or a freshly-downloaded file.
export const DANGEROUS_SCRIPT_RE =
  /\|\s*(?:sh|bash|zsh)\b|\beval\s|node\s+-e\b|python[0-9.]*\s+-c\b|base64\s+-d|(?:curl|wget|fetch)\b[^\n]*\|\s*\w*sh\b|(?:curl|wget|fetch)\b[^\n]*(?:&&|;)\s*(?:sh|bash|zsh|source|\.\/)/iu;

export const INVISIBLE_UNICODE_RE = /[\u200B-\u200F\u2060-\u2064\u202A-\u202E\u2066-\u2069\uFEFF]/u;
export const BIDI_OVERRIDE_RE = /[\u202A-\u202E\u2066-\u2069]/u;
