import React from "react";
import { Box, Text } from "ink";
import chalk from "chalk";
import { Spinner } from "../../scan-ui/components/Spinner.js";
import { deepSummary, type DeepResult } from "../../audit/deep.js";

interface DeepStatusRowProps {
  readonly deep: DeepResult | null;
}

export const DeepStatusRow: React.FC<DeepStatusRowProps> = ({ deep }) => {
  if (deep === null) {
    return (
      <Box paddingLeft={1}>
        <Spinner label="uploading to behavioral scanner…" />
      </Box>
    );
  }
  return (
    <Box paddingLeft={1}>
      <Text>{chalk.dim(`Deep behavioral scan · ${deepSummary(deep)}`)}</Text>
    </Box>
  );
};
