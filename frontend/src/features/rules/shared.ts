import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { RuleSummary } from "@/lib/types";

export const RULES_KEY = ["rules"] as const;

export const LOGIC_LABEL: Record<RuleSummary["logic_type"], string> = {
  match: "Match",
  threshold: "Threshold",
  sequence: "Sequence",
  first_seen: "First seen",
  unknown: "—",
};

export function useToggleRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      api.patch<RuleSummary>(`/api/rules/${id}`, { enabled }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: RULES_KEY });
      void qc.invalidateQueries({ queryKey: ["attack"] });
    },
  });
}
