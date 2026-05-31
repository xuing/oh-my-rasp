{{- define "ohmyrasp.useSecretEnv" -}}
{{- if or .Values.secrets.create .Values.secrets.existingSecret -}}true{{- end -}}
{{- end -}}

{{- define "ohmyrasp.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- .Values.secrets.name -}}
{{- end -}}
{{- end -}}

{{- define "ohmyrasp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default "ohmyrasp-control" .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "ohmyrasp.containerSecurityContext" -}}
{{- $context := deepCopy .Values.containerSecurityContext -}}
{{- if .componentSecurityContext -}}
{{- $context = mergeOverwrite $context .componentSecurityContext -}}
{{- end -}}
{{- toYaml $context -}}
{{- end -}}
