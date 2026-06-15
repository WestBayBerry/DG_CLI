import React, { useEffect, useRef, useState } from "react";
import { Box, Text, useApp, useInput } from "ink";
import { Spinner } from "../scan-ui/components/Spinner.js";
import { renderLogo } from "../scan-ui/logo.js";
import { enterTui, leaveTui } from "../scan-ui/alt-screen.js";
import { dgVersion } from "../commands/version.js";
import { authStatus, displayTier } from "../auth/store.js";
import { resolveWebBase } from "../auth/device-login.js";
import { useLogin } from "../auth/login-app.js";
import { collectAgentOffers, collectAgentSkips } from "../agents/registry.js";
import { markFirstRunShown } from "../runtime/first-run.js";
import { recordLoginNudge } from "../runtime/nudges.js";
import type { CommandResult } from "../commands/types.js";
import { resolvePresentation } from "../presentation/mode.js";
import { createTheme } from "../presentation/theme.js";
import { activateShell, activationOffer } from "../setup/activate-shell.js";
import { commitGuardOffer } from "../setup/git-hook.js";
import { activationCommand, tildifyPath, type SetupPlan } from "../setup/plan.js";
import type { DgPathEnvironment } from "../state/index.js";
import { markSecurityNotesShown, markWizardSkipped, securityNotesShown } from "./gate.js";
import { Selector } from "./selector.js";
import { buildCommitGuardTask, buildWizardTasks, type WizardTask } from "./tasks.js";

type Step = "login" | "login-flow" | "notes" | "choose" | "applying" | "declined" | "fatal" | "done";

export type WizardOutcome =
  | { readonly kind: "done"; readonly email: string; readonly results: readonly TaskLine[] }
  | { readonly kind: "declined" }
  | { readonly kind: "fatal"; readonly detail: string };

export interface TaskLine {
  readonly label: string;
  readonly ok: boolean;
  readonly detail?: string | undefined;
}

export interface AgentSkipLine {
  readonly label: string;
  readonly detail: string;
}

export interface LoginFlowProps {
  readonly webBase: string;
  readonly env: DgPathEnvironment;
  readonly onDone: (email: string) => void;
}

export interface SetupWizardProps {
  readonly version: string;
  readonly notesNeeded: boolean;
  readonly loginNeeded: boolean;
  readonly authedEmail: string;
  readonly sentence: string;
  readonly guardsRepo: boolean;
  readonly skips: readonly AgentSkipLine[];
  readonly tasks: readonly WizardTask[];
  readonly webBase: string;
  readonly env: DgPathEnvironment;
  readonly activateHint: string;
  readonly onNotesAgreed: () => void;
  readonly onLoginSkipped: () => void;
  readonly onOutcome: (outcome: WizardOutcome) => void;
  readonly LoginFlowComponent?: React.ComponentType<LoginFlowProps>;
}

export function protectsSentence(agentLabels: readonly string[]): string {
  if (agentLabels.length === 0) {
    return "Protects npm and pip installs in your shell.";
  }
  if (agentLabels.length === 1) {
    return `Protects npm and pip installs in your shell and in ${agentLabels[0]}.`;
  }
  return `Protects npm and pip installs in your shell and in ${agentLabels.slice(0, -1).join(", ")} and ${agentLabels[agentLabels.length - 1]}.`;
}

const Header: React.FC<{ version: string }> = ({ version }) => (
  <Box flexDirection="column">
    {renderLogo("pass").map((line, i) => (
      <Text key={i}>{line}</Text>
    ))}
    <Text> </Text>
    <Text bold>Dependency Guardian v{version}</Text>
    <Text> </Text>
  </Box>
);

const LoginFlow: React.FC<LoginFlowProps> = ({ webBase, env, onDone }) => {
  const { state, openAndPoll } = useLogin(webBase, env);

  useEffect(() => {
    if (state.phase === "ready") {
      openAndPoll();
    }
  }, [state.phase, openAndPoll]);

  useInput((_input, key) => {
    if (key.return && (state.phase === "success" || state.phase === "expired" || state.phase === "error")) {
      onDone(state.phase === "success" ? state.email : "");
    } else if (key.escape) {
      onDone("");
    }
  });

  switch (state.phase) {
    case "creating":
      return <Spinner label="Creating login session…" />;
    case "ready":
    case "waiting":
      return (
        <Box flexDirection="column">
          <Text>Sign in at:</Text>
          <Text color="cyan">{state.verifyUrl}</Text>
          <Text> </Text>
          <Spinner label="Waiting for you to approve in the browser…" />
          <Text> </Text>
          <Text dimColor>Esc to skip</Text>
        </Box>
      );
    case "success":
      return (
        <Box flexDirection="column">
          <Text color="green" bold>
            ✓ Logged in{state.email ? ` as ${state.email}` : ""}
            {state.plan ? ` (${displayTier(state.plan)} plan)` : ""}
          </Text>
          <Text> </Text>
          <Text dimColor>Login successful. Press Enter to continue…</Text>
        </Box>
      );
    case "expired":
    case "error":
      return (
        <Box flexDirection="column">
          <Text color="yellow">{state.phase === "expired" ? "That login link expired." : `Login failed: ${state.message}.`}</Text>
          <Text dimColor>You can run dg login later. Press Enter to continue…</Text>
        </Box>
      );
  }
};

function hyperlink(label: string, url: string): string {
  return `\u001B]8;;${url}\u0007${label}\u001B]8;;\u0007`;
}

const NotesStep: React.FC<{ termsUrl: string; privacyUrl: string; onAgree: () => void }> = ({ termsUrl, privacyUrl, onAgree }) => {
  useInput((_input, key) => {
    if (key.return) {
      onAgree();
    }
  });
  return (
    <Box flexDirection="column">
      <Text bold>Security notes</Text>
      <Text> </Text>
      <Text>1. dg can make mistakes.</Text>
      <Text>   A PASS verdict does not guarantee a package is safe. You are</Text>
      <Text>   responsible for what you install and should review new</Text>
      <Text>   dependencies.</Text>
      <Text> </Text>
      <Text>2. By continuing you confirm you have read and understand the</Text>
      <Text>
        {"   "}
        <Text color="cyan">{hyperlink("Terms of Service", termsUrl)}</Text> and <Text color="cyan">{hyperlink("Privacy Policy", privacyUrl)}</Text>.
      </Text>
      <Text> </Text>
      <Text dimColor>Press Enter to agree</Text>
    </Box>
  );
};

export const SetupWizardApp: React.FC<SetupWizardProps> = (props) => {
  const { exit } = useApp();
  const [step, setStep] = useState<Step>(props.loginNeeded ? "login" : props.notesNeeded ? "notes" : "choose");
  const [results, setResults] = useState<TaskLine[]>([]);
  const [running, setRunning] = useState<string | null>(null);
  const [fatalDetail, setFatalDetail] = useState("");
  const [email, setEmail] = useState(props.authedEmail);
  const emailRef = useRef(props.authedEmail);
  const applyStarted = useRef(false);
  const Login = props.LoginFlowComponent ?? LoginFlow;

  const afterLogin = (): void => {
    setStep(props.notesNeeded ? "notes" : "choose");
  };

  useInput(
    (_input, key) => {
      if (key.return) {
        exit();
      }
    },
    { isActive: step === "done" }
  );

  useEffect(() => {
    if (step !== "declined" && step !== "fatal") {
      return undefined;
    }
    const timer = setTimeout(() => exit(), 30);
    return () => clearTimeout(timer);
  }, [step, exit]);

  useEffect(() => {
    if (step !== "applying" || applyStarted.current) {
      return undefined;
    }
    applyStarted.current = true;
    let cancelled = false;
    void (async () => {
      const completed: TaskLine[] = [];
      for (const task of props.tasks) {
        if (cancelled) {
          return;
        }
        setRunning(task.label);
        await new Promise<void>((resolve) => setImmediate(resolve));
        let result;
        try {
          result = await task.run();
        } catch (error) {
          result = { ok: false, fatal: true, detail: error instanceof Error ? error.message : "unknown error" };
        }
        if (cancelled) {
          return;
        }
        const line: TaskLine = { label: task.label, ok: result.ok, detail: result.detail };
        completed.push(line);
        setResults((prev) => [...prev, line]);
        if (result.fatal) {
          setRunning(null);
          setFatalDetail(result.detail ?? "");
          props.onOutcome({ kind: "fatal", detail: result.detail ?? "" });
          setStep("fatal");
          return;
        }
      }
      setRunning(null);
      props.onOutcome({ kind: "done", email: emailRef.current, results: completed });
      setStep("done");
    })();
    return () => {
      cancelled = true;
    };
  }, [step, props]);

  return (
    <Box flexDirection="column" paddingLeft={1} paddingTop={1}>
      <Header version={props.version} />
      {step === "login" && (
        <Box flexDirection="column">
          <Text bold>Connect your account</Text>
          <Text> </Text>
          <Selector
            options={[{ label: "Connect in your browser" }, { label: "Skip for now" }]}
            onSelect={(index) => {
              if (index === 0) {
                setStep("login-flow");
              } else {
                props.onLoginSkipped();
                afterLogin();
              }
            }}
            onCancel={() => {
              props.onLoginSkipped();
              afterLogin();
            }}
          />
        </Box>
      )}
      {step === "login-flow" && (
        <Login
          webBase={props.webBase}
          env={props.env}
          onDone={(loggedInEmail) => {
            if (loggedInEmail) {
              setEmail(loggedInEmail);
              emailRef.current = loggedInEmail;
            } else {
              props.onLoginSkipped();
            }
            afterLogin();
          }}
        />
      )}
      {step === "notes" && (
        <NotesStep
          termsUrl={`${props.webBase}/terms`}
          privacyUrl={`${props.webBase}/privacy`}
          onAgree={() => {
            props.onNotesAgreed();
            setStep("choose");
          }}
        />
      )}
      {step === "choose" && (
        <Box flexDirection="column">
          <Text bold>Use recommended settings?</Text>
          <Text> </Text>
          <Text>{props.sentence}</Text>
          {props.guardsRepo && <Text>Also scans this repo's commits before they land.</Text>}
          {props.skips.map((skip) => (
            <Text key={skip.label} dimColor>
              {skip.label} found but skipped — {skip.detail}
            </Text>
          ))}
          <Text> </Text>
          <Selector
            options={[{ label: "Yes, use recommended settings" }, { label: "No, maybe later with dg setup" }]}
            onSelect={(index) => {
              if (index === 0) {
                setStep("applying");
              } else {
                props.onOutcome({ kind: "declined" });
                setStep("declined");
              }
            }}
            onCancel={() => {
              props.onOutcome({ kind: "declined" });
              setStep("declined");
            }}
          />
        </Box>
      )}
      {(step === "applying" || step === "done" || step === "fatal") && (
        <Box flexDirection="column">
          {results.map((line) => (
            <Text key={line.label} color={line.ok ? "green" : "yellow"}>
              {line.ok ? "✓" : "✗"} {line.label}
              {!line.ok && line.detail ? ` — ${line.detail}` : ""}
            </Text>
          ))}
          {running !== null && <Spinner label={running} />}
          {step === "fatal" && (
            <Box flexDirection="column">
              <Text> </Text>
              <Text color="red">{fatalDetail}</Text>
            </Box>
          )}
          {step === "done" && (
            <Box flexDirection="column">
              <Text> </Text>
              <Text>
                <Text color="green" bold>
                  ✓ Setup complete.
                </Text>{" "}
                Activate now: <Text bold>{props.activateHint}</Text>
              </Text>
              {email ? <Text dimColor>Logged in as {email}</Text> : null}
              <Text> </Text>
              <Text dimColor>Press Enter to continue…</Text>
            </Box>
          )}
        </Box>
      )}
      {step === "declined" && <Text dimColor>Run dg setup any time to turn this on.</Text>}
    </Box>
  );
};

export interface RunSetupWizardOptions {
  readonly env?: DgPathEnvironment;
  readonly autoActivate?: boolean;
}

export async function runSetupWizard(plan: SetupPlan, options: RunSetupWizardOptions = {}): Promise<CommandResult> {
  const env = options.env ?? process.env;
  const ci = process.env.CI;
  const restoreCi = ci === "" || ci === "0" || ci === "false";
  if (restoreCi) {
    delete process.env.CI;
  }
  const agents = collectAgentOffers();
  const repo = commitGuardOffer();
  const auth = authStatus(env);
  const state: { outcome: WizardOutcome | null } = { outcome: null };
  const tasks = buildWizardTasks(plan, agents);
  if (repo) {
    tasks.push(buildCommitGuardTask(repo));
  }
  const { render } = await import("ink");
  enterTui();
  const instance = render(
    <SetupWizardApp
      version={dgVersion()}
      notesNeeded={!securityNotesShown(env)}
      loginNeeded={!auth.authenticated}
      authedEmail={auth.email ?? ""}
      sentence={protectsSentence(agents.map((offer) => offer.label))}
      guardsRepo={repo !== null}
      skips={collectAgentSkips()}
      tasks={tasks}
      webBase={resolveWebBase(env)}
      env={env}
      activateHint={activationCommand(plan.shell, tildifyPath(plan.rcPath))}
      onNotesAgreed={() => markSecurityNotesShown(env)}
      onLoginSkipped={() => recordLoginNudge(env)}
      onOutcome={(outcome) => {
        state.outcome = outcome;
      }}
    />,
    { exitOnCtrlC: true }
  );
  await instance.waitUntilExit();
  leaveTui();
  if (restoreCi) {
    process.env.CI = ci;
  }

  const theme = createTheme(resolvePresentation().color);
  const accent = (text: string): string => theme.paint("accent", text);
  const muted = (text: string): string => theme.paint("muted", text);
  const outcome = state.outcome;
  if (outcome === null) {
    // Aborted (e.g. Ctrl-C). Record the skip so the wizard does not re-intercept
    // every subsequent dg command until the user explicitly declines or applies it.
    markWizardSkipped(env);
    markFirstRunShown(env);
    return { exitCode: 0, stdout: "", stderr: "" };
  }
  if (outcome.kind === "declined") {
    markWizardSkipped(env);
    markFirstRunShown(env);
    return { exitCode: 0, stdout: "", stderr: `  ${muted("Run")} ${accent("dg setup")} ${muted("any time to turn this on.")}\n` };
  }
  if (outcome.kind === "fatal") {
    return { exitCode: 1, stdout: "", stderr: `  ${outcome.detail}\n` };
  }
  markFirstRunShown(env);
  const lines = outcome.results.map((line) =>
    line.ok
      ? `  ${theme.paint("pass", `✓ ${line.label}`)}`
      : `  ${theme.paint("warn", `✗ ${line.label}`)}${line.detail ? ` ${muted(`— ${line.detail}`)}` : ""}`
  );
  lines.push(`  ${theme.paint("pass", "✓ dg setup complete — installs are protected in new terminals.")}`);
  if (outcome.email) {
    lines.push(`  ${muted(`Logged in as ${outcome.email}`)}`);
  }
  if (options.autoActivate && activationOffer() === "prompt") {
    process.stderr.write(
      `${lines.join("\n")}\n  ${muted("Starting a protected shell — type")} ${accent("exit")} ${muted("to return to your previous one.")}\n`
    );
    return { exitCode: activateShell(), stdout: "", stderr: "" };
  }
  lines.push(`  ${muted("Activate now:")} ${accent(activationCommand(plan.shell, tildifyPath(plan.rcPath)))}`);
  return { exitCode: 0, stdout: "", stderr: `${lines.join("\n")}\n` };
}
