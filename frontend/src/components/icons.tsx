import type { SVGProps } from "react";

/** Minimal 16px stroke icons drawn for SIGNAL (1.5px stroke, round joins). */
function Icon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...props}
    />
  );
}

export const OverviewIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M1.5 9h3l1.5-4 2.5 7 1.75-5L11.5 9h3" />
  </Icon>
);

export const UsersIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <circle cx="6" cy="5.5" r="2.5" />
    <path d="M1.75 13.5c.6-2.3 2.2-3.5 4.25-3.5s3.65 1.2 4.25 3.5M10.5 3.25a2.25 2.25 0 0 1 0 4.5M12 10.25c1.2.45 2 1.5 2.35 3.25" />
  </Icon>
);

export const AuditIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M4 1.75h5.5L12.5 4.75v9.5H4z" />
    <path d="M9.25 1.75v3.25h3.25M6 8h4.5M6 10.75h4.5" />
  </Icon>
);

export const SearchIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <circle cx="7" cy="7" r="4.5" />
    <path d="m10.5 10.5 3.5 3.5" />
  </Icon>
);

export const SunIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <circle cx="8" cy="8" r="3" />
    <path d="M8 1.5v1.25M8 13.25v1.25M1.5 8h1.25M13.25 8h1.25M3.4 3.4l.9.9M11.7 11.7l.9.9M3.4 12.6l.9-.9M11.7 4.3l.9-.9" />
  </Icon>
);

export const MoonIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M13.5 9.6A5.75 5.75 0 0 1 6.4 2.5a5.75 5.75 0 1 0 7.1 7.1Z" />
  </Icon>
);

export const LogoutIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M6.5 2.25H3.25v11.5H6.5M10.5 11l3-3-3-3M13.5 8H6" />
  </Icon>
);

export const KeyboardIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <rect x="1.5" y="4" width="13" height="8.5" rx="1.5" />
    <path d="M4 7h.01M6.5 7h.01M9 7h.01M11.5 7h.01M5 9.75h6" />
  </Icon>
);

export const ArrowIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M3 8h10M9 4l4 4-4 4" />
  </Icon>
);

export const PlusIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M8 3v10M3 8h10" />
  </Icon>
);

export const UploadIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M8 10.5V2.5M5 5.5l3-3 3 3M2.5 10v2.25c0 .7.55 1.25 1.25 1.25h8.5c.7 0 1.25-.55 1.25-1.25V10" />
  </Icon>
);

export const IngestIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M2 4.5h12M2 8h7M2 11.5h4.5M11.5 9v5M9.25 11.75 11.5 14l2.25-2.25" />
  </Icon>
);

export const RulesIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M8 1.75 13.5 4v4c0 3-2.3 5.3-5.5 6.25C4.8 13.3 2.5 11 2.5 8V4z" />
    <path d="m5.75 8 1.6 1.6 3-3.1" />
  </Icon>
);

export const ExternalIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M9.5 2.5h4v4M13.5 2.5 7.5 8.5M11.5 9.5v3.25c0 .4-.35.75-.75.75h-7.5a.75.75 0 0 1-.75-.75v-7.5c0-.4.35-.75.75-.75H6.5" />
  </Icon>
);

export const AlertsIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <path d="M8 2.25 14 13H2z" />
    <path d="M8 6.5v3M8 11.25h.01" />
  </Icon>
);

export const IncidentsIcon = (p: SVGProps<SVGSVGElement>) => (
  <Icon {...p}>
    <circle cx="3.5" cy="11.5" r="1.5" />
    <circle cx="8" cy="5" r="1.5" />
    <circle cx="12.5" cy="9.5" r="1.5" />
    <path d="M4.4 10.3 7.1 6.2M9.2 5.9l2.4 2.5" />
  </Icon>
);
