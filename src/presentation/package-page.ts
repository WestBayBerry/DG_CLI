const SITE = "https://westbayberry.com";

// Only npm and pypi have public, indexable per-package pages today; cargo and
// other ecosystems have none, so return null rather than link to a 404.
export function packagePageUrl(ecosystem: string, name: string): string | null {
  if (ecosystem !== "npm" && ecosystem !== "pypi") {
    return null;
  }
  return `${SITE}/${ecosystem}/${name}`;
}
