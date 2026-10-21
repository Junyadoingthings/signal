import { useQuery } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { AttackMatrix } from "@/lib/types";

export function useTacticNames(): Map<string, string> {
  const m = useQuery({
    queryKey: ["attack"],
    queryFn: () => api.get<AttackMatrix>("/api/attack"),
    staleTime: 300_000,
  });
  return new Map((m.data?.tactics ?? []).map((t) => [t.shortname, t.name]));
}
