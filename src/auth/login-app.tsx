import React, { useEffect, useRef, useState } from "react";
import { Box, Text, useApp, useInput } from "ink";
import { Spinner } from "../scan-ui/components/Spinner.js";
import { displayTier, writeAuthState } from "./store.js";
import {
  POLL_INTERVAL_MS,
  POLL_TIMEOUT_MS,
  createAuthSession,
  fetchAccountStatus,
  openBrowser,
  pollAuthSession,
  resolveWebBase
} from "./device-login.js";
import type { DgPathEnvironment } from "../state/index.js";

type Phase = "creating" | "ready" | "waiting" | "success" | "expired" | "error";

const SUCCESS_MIN_MS = 600;
const SUCCESS_MAX_MS = 2500;

interface LoginState {
  phase: Phase;
  verifyUrl: string;
  email: string;
  plan: string;
  message: string;
}

export function useLogin(webBase: string, env: DgPathEnvironment): { state: LoginState; tierSettled: React.MutableRefObject<boolean>; openAndPoll: () => void } {
  const [state, setState] = useState<LoginState>({ phase: "creating", verifyUrl: "", email: "", plan: "", message: "" });
  const sessionId = useRef<string>("");
  const started = useRef(false);
  const cancelled = useRef(false);
  const tierSettled = useRef(false);
  const pollTimer = useRef<NodeJS.Timeout | undefined>(undefined);

  useEffect(() => {
    let sessionCancelled = false;
    createAuthSession(webBase, fetch)
      .then((session) => {
        if (sessionCancelled) return;
        sessionId.current = session.sessionId;
        setState((prev) => ({ ...prev, phase: "ready", verifyUrl: session.verifyUrl }));
      })
      .catch((error: unknown) => {
        if (sessionCancelled) return;
        const message = error instanceof Error ? error.message : "could not start login";
        setState((prev) => ({ ...prev, phase: "error", message }));
      });
    return () => {
      sessionCancelled = true;
    };
  }, [webBase]);

  useEffect(() => {
    return () => {
      cancelled.current = true;
      if (pollTimer.current) {
        clearTimeout(pollTimer.current);
        pollTimer.current = undefined;
      }
    };
  }, []);

  const openAndPoll = (): void => {
    if (started.current) return;
    started.current = true;
    openBrowser(state.verifyUrl);
    setState((prev) => ({ ...prev, phase: "waiting" }));
    void (async () => {
      const deadline = Date.now() + POLL_TIMEOUT_MS;
      while (!cancelled.current) {
        const result = await pollAuthSession(webBase, sessionId.current, fetch);
        if (cancelled.current) return;
        if (result.status === "complete" && result.apiKey) {
          const apiKey = result.apiKey;
          const email = result.email ?? "";
          writeAuthState({ token: apiKey, email: result.email });
          setState((prev) => ({ ...prev, phase: "success", email }));
          void fetchAccountStatus(apiKey, env, fetch)
            .then((account) => {
              if (account?.tier) {
                writeAuthState({ token: apiKey, email: result.email, tier: account.tier, name: account.name ?? undefined });
                if (!cancelled.current) {
                  setState((prev) => ({ ...prev, plan: account.tier ?? "" }));
                }
              }
            })
            .finally(() => {
              tierSettled.current = true;
            });
          return;
        }
        if (result.status === "expired") {
          setState((prev) => ({ ...prev, phase: "expired" }));
          return;
        }
        if (Date.now() >= deadline) {
          setState((prev) => ({ ...prev, phase: "error", message: "timed out waiting for browser approval" }));
          return;
        }
        await new Promise<void>((resolve) => {
          pollTimer.current = setTimeout(resolve, POLL_INTERVAL_MS);
        });
      }
    })();
  };

  return { state, tierSettled, openAndPoll };
}

const LoginApp: React.FC<{ webBase: string; env: DgPathEnvironment }> = ({ webBase, env }) => {
  const { state, tierSettled, openAndPoll } = useLogin(webBase, env);
  const { exit } = useApp();

  useEffect(() => {
    if (state.phase === "expired" || state.phase === "error") {
      process.exitCode = 1;
      const timer = setTimeout(() => exit(), 0);
      return () => clearTimeout(timer);
    }
    if (state.phase === "success") {
      process.exitCode = 0;
      const start = Date.now();
      let poll: NodeJS.Timeout | undefined;
      let cap: NodeJS.Timeout | undefined;
      const tick = (): void => {
        if (tierSettled.current && Date.now() - start >= SUCCESS_MIN_MS) {
          exit();
          return;
        }
        poll = setTimeout(tick, 50);
      };
      poll = setTimeout(tick, SUCCESS_MIN_MS);
      cap = setTimeout(() => exit(), SUCCESS_MAX_MS);
      return () => {
        if (poll) clearTimeout(poll);
        if (cap) clearTimeout(cap);
      };
    }
    return undefined;
  }, [state.phase, exit, tierSettled]);

  useInput((_input, key) => {
    if (state.phase === "ready" && key.return) {
      openAndPoll();
    } else if (state.phase === "success") {
      exit();
    }
  });

  switch (state.phase) {
    case "creating":
      return (
        <Box paddingLeft={1} paddingTop={1}>
          <Spinner label="Creating login session…" />
        </Box>
      );
    case "ready":
      return (
        <Box flexDirection="column" paddingLeft={1} paddingTop={1}>
          <Text>Sign in at:</Text>
          <Text color="cyan">{state.verifyUrl}</Text>
          <Text> </Text>
          <Text dimColor>Press Enter to open it in your browser…</Text>
        </Box>
      );
    case "waiting":
      return (
        <Box flexDirection="column" paddingLeft={1} paddingTop={1}>
          <Text>Sign in at:</Text>
          <Text color="cyan">{state.verifyUrl}</Text>
          <Text> </Text>
          <Spinner label="Waiting for you to approve in the browser…" />
        </Box>
      );
    case "success":
      return (
        <Box flexDirection="column" paddingLeft={1} paddingTop={1}>
          <Text color="green" bold>
            ✓ Logged in{state.email ? ` as ${state.email}` : ""}
            {state.plan ? ` (${displayTier(state.plan)} plan)` : ""}
          </Text>
          <Text> </Text>
          <Text dimColor>Run `dg scan` to check your dependencies.</Text>
        </Box>
      );
    case "expired":
      return (
        <Box flexDirection="column" paddingLeft={1} paddingTop={1}>
          <Text color="yellow">That login link expired.</Text>
          <Text dimColor>Run `dg login` to try again.</Text>
        </Box>
      );
    case "error":
      return (
        <Box flexDirection="column" paddingLeft={1} paddingTop={1}>
          <Text color="red">dg login: {state.message}.</Text>
        </Box>
      );
  }
};

export async function runDeviceLoginTui(env: DgPathEnvironment = process.env): Promise<number> {
  const ci = process.env.CI;
  if (ci === "" || ci === "0" || ci === "false") {
    delete process.env.CI;
  }
  const { render } = await import("ink");
  const webBase = resolveWebBase(env);
  const instance = render(<LoginApp webBase={webBase} env={env} />, { exitOnCtrlC: true });
  await instance.waitUntilExit();
  return Number(process.exitCode ?? 0);
}
