import React from "react";
import { Text, Box } from "ink";
import InkSpinner from "ink-spinner";

interface SpinnerProps {
  label: string;
}

export const Spinner: React.FC<SpinnerProps> = ({ label }) => (
  <Box>
    <Text color="cyan">
      <InkSpinner type="dots" />
    </Text>
    <Text> {label}</Text>
  </Box>
);
