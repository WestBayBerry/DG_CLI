import React from "react";
import { Box, Text } from "ink";
import type { SetupIssue } from "../shims.js";

interface SetupBannerProps {
  issues: SetupIssue[];
}

export const SetupBanner: React.FC<SetupBannerProps> = ({ issues }) => {
  if (issues.length === 0) return null;
  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor="yellow"
      paddingLeft={1}
      paddingRight={1}
      width="100%"
    >
      <Text wrap="truncate-end">
        <Text color="yellow" bold>! Setup incomplete</Text>
        <Text dimColor> — {issues.length === 1 ? "1 thing" : `${issues.length} things`} you haven't set up yet</Text>
      </Text>
      {issues.map((issue) => (
        <Text key={issue.id} wrap="truncate-end">
          <Text dimColor>  · </Text>
          {issue.label}
          <Text dimColor> → </Text>
          <Text color="cyan" bold>{issue.fix}</Text>
        </Text>
      ))}
    </Box>
  );
};
