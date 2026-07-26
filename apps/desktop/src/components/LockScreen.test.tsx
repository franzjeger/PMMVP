import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { LockScreen } from "./LockScreen";
import { api, type VaultStatus } from "../lib/api";

vi.mock("../lib/api", async () => {
  const actual = await vi.importActual<typeof import("../lib/api")>("../lib/api");
  return {
    ...actual,
    api: {
      quickUnlock: vi.fn(),
      unlock: vi.fn(),
      createVault: vi.fn(),
    },
  };
});

const quickUnlock = vi.mocked(api.quickUnlock);
const unlock = vi.mocked(api.unlock);

/** An existing vault with Touch ID available — the everyday case. */
function status(overrides: Partial<VaultStatus> = {}): VaultStatus {
  return {
    exists: true,
    unlocked: false,
    hasQuickUnlock: true,
    quickUnlockAvailable: true,
    biometricAvailable: true,
    ...overrides,
  } as VaultStatus;
}

/** The backend's error shape (`CmdError`), which `isApiError` recognises. */
const apiError = (code: string, message: string) => ({ code, message });

beforeEach(() => {
  vi.clearAllMocks();
});

describe("LockScreen", () => {
  it("prompts for Touch ID once on mount", async () => {
    quickUnlock.mockResolvedValue(undefined);
    const onUnlocked = vi.fn();
    render(<LockScreen status={status()} onUnlocked={onUnlocked} />);

    await waitFor(() => expect(onUnlocked).toHaveBeenCalledTimes(1));
    expect(quickUnlock).toHaveBeenCalledTimes(1);
  });

  it("does not prompt at all when quick unlock is unavailable", async () => {
    render(
      <LockScreen
        status={status({ quickUnlockAvailable: false })}
        onUnlocked={vi.fn()}
      />,
    );
    await waitFor(() =>
      expect(screen.getByPlaceholderText("Master password")).toBeInTheDocument(),
    );
    expect(quickUnlock).not.toHaveBeenCalled();
  });

  // REGRESSION (2026-07-20): clicking the empty password field used to re-fire
  // Touch ID. Combined with a failing unlock that produced an endless storm of
  // prompts: 3x Touch ID -> master password -> 3x again.
  it("never triggers Touch ID from clicking or typing in the password field", async () => {
    quickUnlock.mockRejectedValue(apiError("biometric_failed", "Cancelled."));
    const user = userEvent.setup();
    render(<LockScreen status={status()} onUnlocked={vi.fn()} />);

    await waitFor(() => expect(quickUnlock).toHaveBeenCalledTimes(1)); // the mount prompt
    const field = screen.getByPlaceholderText("Master password");
    await user.click(field);
    await user.click(field);
    await user.type(field, "hunter2");

    expect(quickUnlock).toHaveBeenCalledTimes(1); // still just the mount one
  });

  // REGRESSION (2026-07-20): when Touch ID SUCCEEDED but the unlock behind it
  // failed (device key drifted from the header wrap), the error was swallowed
  // and the prompt kept coming back. It must be shown, and prompting must stop.
  it("stops offering Touch ID after a failure past the biometric", async () => {
    quickUnlock.mockRejectedValue(
      apiError("quick_unlock_stale", "Quick unlock is out of sync with this vault."),
    );
    render(<LockScreen status={status()} onUnlocked={vi.fn()} />);

    // The reason is surfaced, not swallowed.
    await waitFor(() =>
      expect(screen.getByText(/out of sync/i)).toBeInTheDocument(),
    );
    // …and the Touch ID affordance is gone, so it cannot be fired again.
    expect(screen.queryByRole("button", { name: /use touch id/i })).toBeNull();
    expect(quickUnlock).toHaveBeenCalledTimes(1);
  });

  it("stays quiet when the user simply cancels the automatic prompt", async () => {
    quickUnlock.mockRejectedValue(apiError("biometric_failed", "Cancelled."));
    render(<LockScreen status={status()} onUnlocked={vi.fn()} />);

    await waitFor(() => expect(quickUnlock).toHaveBeenCalledTimes(1));
    // No scary error for a deliberate cancel, and Touch ID stays available.
    expect(screen.queryByText(/cancelled/i)).toBeNull();
    expect(
      screen.getByRole("button", { name: /use touch id/i }),
    ).toBeInTheDocument();
  });

  it("retries on demand via the Touch ID button, and reports why it failed", async () => {
    quickUnlock.mockRejectedValue(apiError("biometric_failed", "Not recognised."));
    const user = userEvent.setup();
    render(<LockScreen status={status()} onUnlocked={vi.fn()} />);
    await waitFor(() => expect(quickUnlock).toHaveBeenCalledTimes(1));

    await user.click(screen.getByRole("button", { name: /use touch id/i }));

    expect(quickUnlock).toHaveBeenCalledTimes(2);
    await waitFor(() =>
      expect(screen.getByText(/not recognised/i)).toBeInTheDocument(),
    );
  });

  it("unlocks with the master password", async () => {
    quickUnlock.mockRejectedValue(apiError("biometric_failed", "Cancelled."));
    unlock.mockResolvedValue(undefined);
    const onUnlocked = vi.fn();
    const user = userEvent.setup();
    render(<LockScreen status={status()} onUnlocked={onUnlocked} />);

    await user.type(screen.getByPlaceholderText("Master password"), "correct horse");
    await user.click(screen.getByRole("button", { name: "Unlock" }));

    await waitFor(() => expect(unlock).toHaveBeenCalledWith("correct horse"));
    expect(onUnlocked).toHaveBeenCalled();
  });

  it("shows the reason when the master password is wrong", async () => {
    quickUnlock.mockRejectedValue(apiError("biometric_failed", "Cancelled."));
    unlock.mockRejectedValue(
      apiError("invalid_credentials", "That master password is not correct."),
    );
    const onUnlocked = vi.fn();
    const user = userEvent.setup();
    render(<LockScreen status={status()} onUnlocked={onUnlocked} />);

    await user.type(screen.getByPlaceholderText("Master password"), "wrong");
    await user.click(screen.getByRole("button", { name: "Unlock" }));

    await waitFor(() =>
      expect(screen.getByText(/not correct/i)).toBeInTheDocument(),
    );
    expect(onUnlocked).not.toHaveBeenCalled();
  });

  it("requires a confirmed, long-enough password when creating a vault", async () => {
    const onUnlocked = vi.fn();
    const user = userEvent.setup();
    render(
      <LockScreen status={status({ exists: false })} onUnlocked={onUnlocked} />,
    );

    const pw = screen.getByPlaceholderText("Master password");
    const confirm = screen.getByPlaceholderText("Confirm master password");
    const submit = screen.getByRole("button", { name: "Create Vault" });

    await user.type(pw, "short");
    await user.click(submit);
    expect(screen.getByText(/at least 8 characters/i)).toBeInTheDocument();
    expect(api.createVault).not.toHaveBeenCalled();

    await user.clear(pw);
    await user.type(pw, "long-enough-pw");
    await user.type(confirm, "different-pw");
    await user.click(submit);
    expect(screen.getByText(/don't match/i)).toBeInTheDocument();
    expect(api.createVault).not.toHaveBeenCalled();
  });
});
