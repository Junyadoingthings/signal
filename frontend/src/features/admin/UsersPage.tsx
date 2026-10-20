import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import { PlusIcon } from "@/components/icons";
import { Button, Dialog, Field, Input, PageHeader, Panel, Select } from "@/components/ui";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { formatRelative } from "@/lib/format";
import type { Role, User } from "@/lib/types";

const USERS_KEY = ["users"] as const;

export function UsersPage() {
  const qc = useQueryClient();
  const { user: me } = useAuth();
  const [creating, setCreating] = useState(false);
  const [rowError, setRowError] = useState<string | null>(null);
  const users = useQuery({ queryKey: USERS_KEY, queryFn: () => api.get<User[]>("/api/users") });

  const update = useMutation({
    mutationFn: ({ id, patch }: { id: number; patch: Partial<Pick<User, "role" | "is_active">> }) =>
      api.patch<User>(`/api/users/${id}`, patch),
    onSuccess: () => {
      setRowError(null);
      void qc.invalidateQueries({ queryKey: USERS_KEY });
    },
    onError: (e) => {
      setRowError(e instanceof ApiError ? e.message : "Update failed");
    },
  });

  return (
    <div className="mx-auto max-w-5xl">
      <PageHeader
        title="Users"
        description="Admins manage rules and users. Analysts triage."
        actions={
          <Button
            variant="primary"
            onClick={() => {
              setCreating(true);
            }}
          >
            <PlusIcon className="size-3.5" /> New user
          </Button>
        }
      />
      {rowError ? (
        <p role="alert" className="mb-3 text-xs text-danger">
          {rowError}
        </p>
      ) : null}
      <Panel className="overflow-x-auto">
        <table className="w-full min-w-[40rem] text-left">
          <thead>
            <tr className="border-b border-border">
              {["Name", "Email", "Role", "Status", "Last login"].map((h) => (
                <th key={h} scope="col" className="label-caps px-4 py-2.5 font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {users.isPending
              ? Array.from({ length: 3 }, (_, i) => (
                  <tr key={i} className="border-b border-border last:border-0">
                    {Array.from({ length: 5 }, (__, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="skeleton h-4 w-24" />
                      </td>
                    ))}
                  </tr>
                ))
              : (users.data ?? []).map((u) => (
                  <tr
                    key={u.id}
                    className="border-b border-border last:border-0 hover:bg-surface-2/60"
                  >
                    <td className="px-4 py-2.5">
                      {u.display_name}
                      {u.id === me?.id ? (
                        <span className="ml-2 text-2xs text-fg-faint">you</span>
                      ) : null}
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-fg-muted">{u.email}</td>
                    <td className="px-4 py-2.5">
                      <Select
                        aria-label={`Role for ${u.email}`}
                        value={u.role}
                        className="h-7 w-28 text-xs"
                        onChange={(e) => {
                          update.mutate({ id: u.id, patch: { role: e.target.value as Role } });
                        }}
                      >
                        <option value="analyst">Analyst</option>
                        <option value="admin">Admin</option>
                      </Select>
                    </td>
                    <td className="px-4 py-2.5">
                      <Button
                        size="sm"
                        variant={u.is_active ? "ghost" : "secondary"}
                        aria-label={`${u.is_active ? "Deactivate" : "Activate"} ${u.email}`}
                        onClick={() => {
                          update.mutate({ id: u.id, patch: { is_active: !u.is_active } });
                        }}
                      >
                        <span
                          aria-hidden="true"
                          className={
                            u.is_active
                              ? "size-1.5 rounded-full bg-ok"
                              : "size-1.5 rounded-full bg-fg-faint"
                          }
                        />
                        {u.is_active ? "Active" : "Disabled"}
                      </Button>
                    </td>
                    <td className="px-4 py-2.5 text-fg-muted">{formatRelative(u.last_login_at)}</td>
                  </tr>
                ))}
          </tbody>
        </table>
      </Panel>
      <CreateUserDialog
        open={creating}
        onClose={() => {
          setCreating(false);
        }}
      />
    </div>
  );
}

function CreateUserDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState({
    email: "",
    display_name: "",
    role: "analyst" as Role,
    password: "",
  });
  const [error, setError] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => api.post<User>("/api/users", form),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: USERS_KEY });
      setForm({ email: "", display_name: "", role: "analyst", password: "" });
      setError(null);
      onClose();
    },
    onError: (e) => {
      setError(
        e instanceof ApiError
          ? e.code === "validation_error"
            ? "Check the fields: password needs 12+ characters."
            : e.message
          : "Failed",
      );
    },
  });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    create.mutate();
  };

  return (
    <Dialog open={open} onClose={onClose} title="New user">
      <form onSubmit={submit} className="flex flex-col gap-4">
        <Field label="Display name" htmlFor="nu-name">
          <Input
            id="nu-name"
            required
            value={form.display_name}
            onChange={(e) => {
              setForm({ ...form, display_name: e.target.value });
            }}
          />
        </Field>
        <Field label="Email" htmlFor="nu-email">
          <Input
            id="nu-email"
            type="email"
            required
            value={form.email}
            onChange={(e) => {
              setForm({ ...form, email: e.target.value });
            }}
          />
        </Field>
        <Field label="Role" htmlFor="nu-role">
          <Select
            id="nu-role"
            value={form.role}
            onChange={(e) => {
              setForm({ ...form, role: e.target.value as Role });
            }}
          >
            <option value="analyst">Analyst — triage alerts and incidents</option>
            <option value="admin">Admin — also manage rules and users</option>
          </Select>
        </Field>
        <Field
          label="Initial password"
          htmlFor="nu-pw"
          hint="At least 12 characters. Share it out of band."
        >
          <Input
            id="nu-pw"
            type="password"
            autoComplete="new-password"
            minLength={12}
            required
            value={form.password}
            onChange={(e) => {
              setForm({ ...form, password: e.target.value });
            }}
          />
        </Field>
        {error ? (
          <p role="alert" className="text-xs text-danger">
            {error}
          </p>
        ) : null}
        <div className="mt-2 flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button type="submit" variant="primary" disabled={create.isPending}>
            Create user
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
