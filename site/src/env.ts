export interface Env {
  FEED: R2Bucket;
  FETCHES?: AnalyticsEngineDataset;
  REMOVAL_LIMIT?: RateLimit;
  LOOKUP_LIMIT?: RateLimit;
  SHADOW?: string;
  SHADOW_AUTH?: string;
  GITHUB_REPO: string;
  GITHUB_REF: string;
  REMOVAL_UPSTREAM: string;
  FEED_PROXY_SECRET?: string;
  TURNSTILE_SITEKEY: string;
  TURNSTILE_SECRET?: string;
  ALERT?: SendEmail;
  ALERT_TO: string;
}

export const isShadow = (env: Env): boolean => env.SHADOW === "1";
