import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { Markdown } from "./Activity";

describe("notes markdown", () => {
  it("renders formatting but never raw HTML, scripts, images or javascript: links", () => {
    const { container } = render(
      <Markdown
        text={
          '**bold** and `code`\n\n<script>alert(1)</script><img src="https://evil.example/p.gif">\n\n![pixel](https://evil.example/t.gif)\n\n[click](javascript:alert(1)) [ok](https://attack.mitre.org)'
        }
      />,
    );
    expect(container.querySelector("strong")?.textContent).toBe("bold");
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    const links = [...container.querySelectorAll("a")];
    expect(links.map((a) => a.getAttribute("href"))).not.toContain("javascript:alert(1)");
    const ok = links.find((a) => a.textContent === "ok");
    expect(ok?.getAttribute("rel")).toContain("noopener");
    expect(ok?.getAttribute("target")).toBe("_blank");
  });
});
