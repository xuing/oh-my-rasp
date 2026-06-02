import { useEffect, useState } from "react";
import { Boxes, KeyRound, Plus, Trash2 } from "lucide-react";
import { api, type Application } from "../lib/api";
import { selectApplication, useAppScope } from "../lib/app-context";
import { focusStoredSection } from "../lib/focus";
import { useApplications, useInvalidator, useMutation } from "../lib/queries";
import { PageHeader, Grid } from "../components/page";
import { Badge, Button, Field, Mono, Panel, QueryState, SelectInput, Table, Td, TextInput, Th } from "../components/ui";
import { isPrivileged } from "../lib/session";
import { shortDateTime, shortId } from "../lib/format";
import { useT } from "../i18n";

export function ApplicationsPage() {
  const t = useT();
  useEffect(focusStoredSection, []);
  return (
    <>
      <PageHeader
        eyebrow={t("Inventory")}
        title={t("Applications")}
        description={t("Create applications, manage environments, and rotate bootstrap secrets used by agents.")}
      />
      <ApplicationsBody />
    </>
  );
}

function ApplicationsBody() {
  const t = useT();
  const apps = useApplications();
  const scope = useAppScope();
  const invalidate = useInvalidator();
  const privileged = isPrivileged();
  const selectedApp = apps.data?.find((a) => a.id === scope.applicationId) ?? apps.data?.[0] ?? null;
  const [message, setMessage] = useState("");

  const create = useMutation({
    mutationFn: (input: { name: string; description?: string }) => api.createApplication(input),
    onSuccess: (app) => {
      selectApplication(app.id);
      setMessage(app.secret ? t("Application created. Secret: {secret}", { secret: app.secret }) : t("Application created."));
      invalidate("applications");
    }
  });
  const env = useMutation({
    mutationFn: (input: { appID: string; name: string; kind?: string }) =>
      api.createEnvironment(input.appID, { name: input.name, kind: input.kind }),
    onSuccess: () => {
      setMessage(t("Environment created."));
      invalidate("applications");
    }
  });
  const rotate = useMutation({
    mutationFn: (id: string) => api.rotateSecret(id),
    onSuccess: (app) => {
      setMessage(app.secret ? t("Secret rotated. New secret: {secret}", { secret: app.secret }) : t("Secret rotated."));
      invalidate("applications");
    }
  });
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteApplication(id),
    onSuccess: () => {
      setMessage(t("Application deleted."));
      invalidate("applications");
    }
  });

  return (
    <div className="space-y-4" data-section="applications" tabIndex={-1}>
      {message && <div className="rounded-md border border-signal/30 bg-signal/5 px-3 py-2 text-[13px] text-signal">{message}</div>}
      <Grid className="lg:grid-cols-[1.4fr_1fr]">
        <Panel title={t("Application inventory")} eyebrow={t("Scope")} flush>
          <QueryState
            isLoading={apps.isLoading}
            isError={apps.isError}
            error={apps.error}
            isEmpty={(apps.data ?? []).length === 0}
            emptyTitle={t("No applications")}
            emptyHint={t("Create an application before registering agents.")}
            emptyIcon={<Boxes className="h-5 w-5" />}
          >
            <Table>
              <thead>
                <tr>
                  <Th>{t("Application")}</Th>
                  <Th>{t("Environments")}</Th>
                  <Th>{t("Policy")}</Th>
                  <Th>{t("Created")}</Th>
                  <Th>{t("Actions")}</Th>
                </tr>
              </thead>
              <tbody>
                {(apps.data ?? []).map((app) => (
                  <ApplicationRow
                    key={app.id}
                    app={app}
                    selected={app.id === selectedApp?.id}
                    privileged={privileged}
                    busy={rotate.isPending || remove.isPending}
                    onSelect={() => selectApplication(app.id)}
                    onRotate={() => rotate.mutate(app.id)}
                    onDelete={() => {
                      if (window.confirm(t("Delete this application? Agents and audit history are retained."))) remove.mutate(app.id);
                    }}
                  />
                ))}
              </tbody>
            </Table>
          </QueryState>
        </Panel>

        <div className="space-y-4">
          <ApplicationForm disabled={!privileged || create.isPending} onSubmit={(input) => create.mutate(input)} />
          <EnvironmentForm
            applications={apps.data ?? []}
            defaultAppID={selectedApp?.id ?? ""}
            disabled={!privileged || env.isPending}
            onSubmit={(input) => env.mutate(input)}
          />
          {!privileged && (
            <p className="text-[12px] text-faint">{t("You have read-only access. Administrators and security engineers can manage applications.")}</p>
          )}
        </div>
      </Grid>
    </div>
  );
}

function ApplicationRow({
  app,
  selected,
  privileged,
  busy,
  onSelect,
  onRotate,
  onDelete
}: {
  app: Application;
  selected: boolean;
  privileged: boolean;
  busy: boolean;
  onSelect: () => void;
  onRotate: () => void;
  onDelete: () => void;
}) {
  const t = useT();
  return (
    <tr>
      <Td>
        <button type="button" className="text-left text-[13px] font-medium text-ink hover:text-signal" onClick={onSelect}>
          {app.name}
        </button>
        <div className="flex items-center gap-2">
          <Mono className="text-[11px] text-faint">{app.id}</Mono>
          {selected && <Badge tone="signal">{t("selected")}</Badge>}
        </div>
      </Td>
      <Td>
        <div className="flex flex-wrap gap-1">
          {(app.environment_ids ?? []).length === 0 ? (
            <span className="text-faint">{t("No environments")}</span>
          ) : (
            (app.environment_ids ?? []).map((id) => <Badge key={id}>{shortId(id)}</Badge>)
          )}
        </div>
      </Td>
      <Td>{app.policy_id ? <Badge tone="signal">v{app.policy_version ?? "?"}</Badge> : <span className="text-faint">{t("unassigned")}</span>}</Td>
      <Td>{shortDateTime(app.created_at)}</Td>
      <Td>
        <div className="flex items-center gap-1">
          {privileged && (
            <>
              <Button size="sm" variant="subtle" title={t("Rotate secret")} onClick={onRotate} disabled={busy}>
                <KeyRound className="h-3.5 w-3.5" />
              </Button>
              <Button size="sm" variant="subtle" title={t("Delete")} className="hover:text-critical" onClick={onDelete} disabled={busy}>
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </>
          )}
        </div>
      </Td>
    </tr>
  );
}

function ApplicationForm({
  disabled,
  onSubmit
}: {
  disabled: boolean;
  onSubmit: (input: { name: string; description?: string }) => void;
}) {
  const t = useT();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  return (
    <Panel title={t("Create application")} eyebrow={t("Inventory")}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!name.trim()) return;
          onSubmit({ name: name.trim(), description: description.trim() || undefined });
          setName("");
          setDescription("");
        }}
      >
        <Field label={t("Name")}>
          <TextInput value={name} disabled={disabled} onChange={(e) => setName(e.target.value)} required />
        </Field>
        <Field label={t("Description")}>
          <TextInput value={description} disabled={disabled} onChange={(e) => setDescription(e.target.value)} />
        </Field>
        <Button type="submit" variant="primary" disabled={disabled || !name.trim()}>
          <Plus className="h-3.5 w-3.5" /> {t("Create")}
        </Button>
      </form>
    </Panel>
  );
}

function EnvironmentForm({
  applications,
  defaultAppID,
  disabled,
  onSubmit
}: {
  applications: Application[];
  defaultAppID: string;
  disabled: boolean;
  onSubmit: (input: { appID: string; name: string; kind?: string }) => void;
}) {
  const t = useT();
  const [appID, setAppID] = useState(defaultAppID);
  const [name, setName] = useState("");
  const [kind, setKind] = useState("prod");

  useEffect(() => {
    if (!appID && defaultAppID) setAppID(defaultAppID);
  }, [appID, defaultAppID]);

  return (
    <Panel title={t("Create environment")} eyebrow={t("Deployment")}>
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!appID || !name.trim()) return;
          onSubmit({ appID, name: name.trim(), kind: kind.trim() || undefined });
          setName("");
        }}
      >
        <Field label={t("Application")}>
          <SelectInput value={appID} disabled={disabled || applications.length === 0} onChange={(e) => setAppID(e.target.value)}>
            {applications.map((app) => (
              <option key={app.id} value={app.id}>
                {app.name}
              </option>
            ))}
          </SelectInput>
        </Field>
        <Field label={t("Name")}>
          <TextInput value={name} disabled={disabled} onChange={(e) => setName(e.target.value)} placeholder="production" required />
        </Field>
        <Field label={t("Kind")}>
          <SelectInput value={kind} disabled={disabled} onChange={(e) => setKind(e.target.value)}>
            <option value="prod">{t("Production")}</option>
            <option value="stage">{t("Staging")}</option>
            <option value="dev">{t("Development")}</option>
          </SelectInput>
        </Field>
        <Button type="submit" variant="primary" disabled={disabled || !appID || !name.trim()}>
          <Plus className="h-3.5 w-3.5" /> {t("Create")}
        </Button>
      </form>
    </Panel>
  );
}
