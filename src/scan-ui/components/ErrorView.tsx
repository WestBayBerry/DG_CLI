import React from "react";
import { Text, Box } from "ink";
import chalk from "chalk";
import { sanitize } from "../../security/sanitize.js";

interface ErrorViewProps {
  error: Error;
}

function getHint(error: Error): string | null {
  const statusCode = (error as Error & { statusCode?: number }).statusCode;
  if (typeof statusCode !== "number") return null;

  switch (statusCode) {
    case 401:
      return "Not authenticated. Run `dg login` to sign in.";
    case 429:
      return "Rate limit exceeded. Upgrade at westbayberry.com/pricing";
    case 504:
      return "Server timeout. Try scanning fewer packages.";
    default:
      return null;
  }
}

export const ErrorView: React.FC<ErrorViewProps> = ({ error }) => {
  const hint = getHint(error);

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor="red"
      paddingLeft={1}
      paddingRight={1}
    >
      <Text>
        {chalk.red.bold("\u2718 Error")}
      </Text>
      <Text>{sanitize(error.message)}</Text>
      {hint && (
        <Text>
          {chalk.yellow("\u2192")} {hint}
        </Text>
      )}
    </Box>
  );
};
