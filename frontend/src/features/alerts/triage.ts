import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { AlertRow, AlertStatus, TriagePatch, UserBrief, Verdict } from "@/lib/types";

export const STATUS_LABEL: Record<AlertStatus, string> = {
  new: "New",
  investigating: "Investigating",
  closed: "Closed",
};

export const VERDICT_LABEL: Record<Verdict, string> = {
  true_positive: "True positive",
  false_positive: "False positive",
  benign_true_positive: "Benign true positive",
};

export const VERDICT_SHORT: Record<Verdict, string> = {
  true_positive: "TP",
  false_positive: "FP",
  benign_true_positive: "BTP",
};

export function useTriage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, patch }: { id: number; patch: TriagePatch }) =>
      api.patch<AlertRow>(`/api/alerts/${String(id)}`, patch),
    onSuccess: (row) => {
      void qc.invalidateQueries({ queryKey: ["alerts"] });
      void qc.invalidateQueries({ queryKey: ["incidents"] });
      void qc.invalidateQueries({ queryKey: ["alert", row.id] });
    },
  });
}

export function useBulkTriage() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ ids, patch }: { ids: number[]; patch: TriagePatch }) =>
      api.post<{ updated: number[]; errors: Record<string, string> }>("/api/alerts/bulk", {
        ids,
        ...patch,
      }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["alerts"] });
      void qc.invalidateQueries({ queryKey: ["incidents"] });
      void qc.invalidateQueries({ queryKey: ["alert"] });
    },
  });
}

export function useDirectory() {
  return useQuery({
    queryKey: ["users", "directory"],
    queryFn: () => api.get<UserBrief[]>("/api/users/directory"),
    staleTime: 5 * 60_000,
  });
}
