import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RawLog } from "./RawLog";
import { tokenize } from "./tokenize";

describe("RawLog", () => {
  it("renders attacker-controlled markup as literal text", () => {
    const evil =
      '198.51.100.7 - - [20/Oct/2026:10:00:00 +0000] "GET /<script>alert(1)</script>" 404 0 "-" "<img src=x onerror=alert(1)>"';
    const { container } = render(<RawLog raw={evil} />);
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toBe(evil);
  });

  it("highlights timestamps, IPs and strings without changing the text", () => {
    const line =
      'Oct 20 03:14:09 web01 sshd[1]: Failed password for root from 203.0.113.50 port 22 user="x"';
    const tokens = tokenize(line);
    expect(tokens.map((t) => t.text).join("")).toBe(line);
    expect(tokens.find((t) => t.kind === "ts")?.text).toBe("Oct 20 03:14:09");
    expect(tokens.find((t) => t.kind === "ip")?.text).toBe("203.0.113.50");
    expect(tokens.find((t) => t.kind === "str")?.text).toBe('"x"');
  });

  it("caps very long records", () => {
    const tokens = tokenize("a".repeat(25_000));
    expect(tokens.map((t) => t.text).join("")).toContain("5000 more characters");
  });
});
