// ============================================================
// Scanner Metadata Constants
// ============================================================
// This file contains ONLY pure constants and types with NO
// server-side imports (no next/headers, no postgres, no auth).
// Safe to import from both server and client components.
// ============================================================

/** All available input (prompt) scanner names */
export const ALL_INPUT_SCANNERS = [
  "anonymize",
  "ban_code",
  "ban_competitors",
  "ban_substrings",
  "ban_topics",
  "code",
  "gibberish",
  "invisible_text",
  "language",
  "prompt_injection",
  "regex",
  "secrets",
  "sentiment",
  "token_limit",
  "toxicity",
] as const;

/** All available output scanner names */
export const ALL_OUTPUT_SCANNERS = [
  "ban_code",
  "ban_competitors",
  "ban_substrings",
  "ban_topics",
  "bias",
  "code",
  "deanonymize",
  "json",
  "language",
  "language_same",
  "malicious_urls",
  "no_refusal",
  "reading_time",
  "factual_consistency",
  "gibberish",
  "regex",
  "relevance",
  "sensitive",
  "sentiment",
  "toxicity",
  "url_reachability",
] as const;

export type InputScannerName = (typeof ALL_INPUT_SCANNERS)[number];
export type OutputScannerName = (typeof ALL_OUTPUT_SCANNERS)[number];

/** Human-readable labels and descriptions for every scanner */
export const SCANNER_META: Record<
  string,
  {
    label: string;
    description: string;
    category: string;
    requiresSettings?: boolean;
    settingsHint?: string;
  }
> = {
  // ── Input scanners ──────────────────────────────────────
  anonymize: {
    label: "Anonymize (PII)",
    description:
      "Detects and redacts personally identifiable information such as names, emails, phone numbers, SSNs, and credit cards.",
    category: "Privacy",
    settingsHint:
      '{"entity_types":["PERSON","EMAIL","PHONE_NUMBER"],"use_faker":false,"language":"en"}',
  },
  ban_code: {
    label: "Ban Code",
    description:
      "Detects and blocks code snippets in specific programming languages.",
    category: "Content",
    settingsHint: '{"languages":["python","javascript"],"is_blocked":true}',
  },
  ban_competitors: {
    label: "Ban Competitors",
    description:
      "Identifies and optionally redacts mentions of competitor organizations.",
    category: "Business",
    requiresSettings: true,
    settingsHint: '{"competitors":["CompanyA","CompanyB"],"redact":false}',
  },
  ban_substrings: {
    label: "Ban Substrings",
    description:
      "Blocks prompts containing specified banned substrings or words.",
    category: "Content",
    requiresSettings: true,
    settingsHint:
      '{"substrings":["badword1","badword2"],"match_type":"word","case_sensitive":false}',
  },
  ban_topics: {
    label: "Ban Topics",
    description:
      "Uses zero-shot classification to block specific topics like violence, religion, etc.",
    category: "Content",
    requiresSettings: true,
    settingsHint: '{"topics":["violence","religion","politics"]}',
  },
  code: {
    label: "Code Detection",
    description:
      "Detects code in the prompt. Can allow or block specific languages.",
    category: "Content",
    settingsHint: '{"languages":["python"],"is_blocked":false}',
  },
  gibberish: {
    label: "Gibberish",
    description:
      "Detects nonsensical or gibberish input that could waste LLM resources.",
    category: "Quality",
  },
  invisible_text: {
    label: "Invisible Text",
    description:
      "Detects invisible unicode characters that may be used for prompt injection.",
    category: "Security",
  },
  language: {
    label: "Language",
    description: "Ensures the prompt is in an allowed language.",
    category: "Quality",
    settingsHint: '{"valid_languages":["en","es","fr"]}',
  },
  prompt_injection: {
    label: "Prompt Injection",
    description:
      "Detects prompt injection and jailbreak attempts using ML classification.",
    category: "Security",
  },
  regex: {
    label: "Regex Pattern",
    description:
      "Matches custom regex patterns to detect or redact specific content.",
    category: "Custom",
    requiresSettings: true,
    settingsHint:
      '{"patterns":["\\\\d{3}-\\\\d{2}-\\\\d{4}"],"match_type":"search","redact":true}',
  },
  secrets: {
    label: "Secrets",
    description:
      "Detects API keys, tokens, passwords, and other secrets in the prompt.",
    category: "Security",
  },
  sentiment: {
    label: "Sentiment",
    description: "Analyzes prompt sentiment and flags overly negative content.",
    category: "Quality",
  },
  token_limit: {
    label: "Token Limit",
    description:
      "Ensures the prompt does not exceed a maximum token count (DoS protection).",
    category: "Security",
    settingsHint: '{"limit":4096,"encoding_name":"cl100k_base"}',
  },
  toxicity: {
    label: "Toxicity",
    description: "Detects toxic, offensive, or hateful content.",
    category: "Safety",
  },
  // ── Output scanners ─────────────────────────────────────
  bias: {
    label: "Bias",
    description: "Detects biased or prejudiced content in LLM output.",
    category: "Safety",
  },
  deanonymize: {
    label: "Deanonymize",
    description:
      "Restores previously anonymized entities back to their original values.",
    category: "Privacy",
  },
  json: {
    label: "JSON Validation",
    description:
      "Validates that the output is well-formed JSON and optionally repairs it.",
    category: "Quality",
    settingsHint: '{"required_elements":0,"repair":true}',
  },
  language_same: {
    label: "Language Same",
    description: "Ensures the output language matches the input language.",
    category: "Quality",
  },
  malicious_urls: {
    label: "Malicious URLs",
    description: "Detects malicious or phishing URLs in the output.",
    category: "Security",
  },
  no_refusal: {
    label: "No Refusal",
    description:
      "Detects when the LLM refuses to answer a legitimate question.",
    category: "Quality",
  },
  reading_time: {
    label: "Reading Time",
    description: "Ensures the output can be read within a maximum time limit.",
    category: "Quality",
    settingsHint: '{"max_seconds":60,"truncate":false}',
  },
  factual_consistency: {
    label: "Factual Consistency",
    description:
      "Checks if the output is factually consistent with the input prompt.",
    category: "Quality",
  },
  relevance: {
    label: "Relevance",
    description: "Checks if the output is relevant to the input prompt.",
    category: "Quality",
  },
  sensitive: {
    label: "Sensitive Data",
    description:
      "Detects sensitive information (PII, credentials) leaking in the output.",
    category: "Privacy",
    settingsHint: '{"entity_types":["PERSON","EMAIL"],"redact":true}',
  },
  url_reachability: {
    label: "URL Reachability",
    description:
      "Checks whether URLs in the output are reachable and return valid status codes.",
    category: "Quality",
    settingsHint: '{"success_status_codes":[200,301,302]}',
  },
};
