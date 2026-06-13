import React, { useState } from "react";
import { Box, Text, useInput } from "ink";

export interface SelectorOption {
  readonly label: string;
}

interface Props {
  readonly options: readonly SelectorOption[];
  readonly onSelect: (index: number) => void;
  readonly onCancel: () => void;
}

export const Selector: React.FC<Props> = ({ options, onSelect, onCancel }) => {
  const [cursor, setCursor] = useState(0);

  useInput((input, key) => {
    if (key.upArrow || input === "k") {
      setCursor((c) => Math.max(0, c - 1));
    } else if (key.downArrow || input === "j") {
      setCursor((c) => Math.min(options.length - 1, c + 1));
    } else if (key.return) {
      onSelect(cursor);
    } else if (key.escape) {
      onCancel();
    } else if (/^[1-9]$/.test(input)) {
      const index = Number(input) - 1;
      if (index < options.length) {
        onSelect(index);
      }
    }
  });

  return (
    <Box flexDirection="column">
      {options.map((option, i) => (
        <Text key={i} {...(i === cursor ? { color: "cyan" } : {})}>
          {i === cursor ? "❯" : " "} {i + 1}. {option.label}
        </Text>
      ))}
      <Text> </Text>
      <Text dimColor>Enter to confirm · arrows or number keys to choose · Esc to skip</Text>
    </Box>
  );
};
