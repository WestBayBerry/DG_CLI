type EnvLike = { readonly [key: string]: string | undefined };

// DG_API_KEY is the documented public name for the CI auth token (every docs page,
// the settings UI, and the CLI reference use it); DG_API_TOKEN is the historical
// alias kept for back-compat. Accept either so CI that follows the docs works.
export function envAuthToken(env: EnvLike): string | undefined {
  return env.DG_API_KEY || env.DG_API_TOKEN || undefined;
}
