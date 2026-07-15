import { useEffect, useMemo, useState } from 'react'
import { api } from '../lib/api.js'
import PageHeader from '../components/PageHeader.jsx'

const PROVIDER_ENV = {
  ollama: ['OLLAMA_BASE_URL'],
  openai: ['OPENAI_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_MODEL'],
  chatgpt: ['OPENAI_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_MODEL'],
  openai_compatible: ['OPENAI_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_MODEL'],
  anthropic: ['ANTHROPIC_API_KEY', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_MODEL'],
  claude_api: ['ANTHROPIC_API_KEY', 'ANTHROPIC_BASE_URL', 'ANTHROPIC_MODEL'],
  codex_cli: ['CODEX_CLI_PATH'],
  claude_cli: ['CLAUDE_CLI_PATH'],
}
const PROVIDER_ENV_KEYS = new Set(Object.values(PROVIDER_ENV).flat())

function RuntimeField({ field, value, onChange }) {
  if (field.type === 'boolean') {
    return <label className="flex items-center justify-between gap-4 rounded-lg border border-border p-3"><span><span className="block text-sm text-text">{field.label}</span>{field.description ? <span className="mt-1 block text-xs leading-5 text-dim">{field.description}</span> : null}</span><input type="checkbox" checked={Boolean(value)} onChange={(event) => onChange(event.target.checked)} /></label>
  }
  return <label className="block"><span className="mb-1 block font-mono text-[11px] uppercase tracking-[0.12em] text-dim">{field.label}</span>{field.type === 'select' ? <select className="input w-full" value={value ?? ''} onChange={(event) => onChange(event.target.value)}>{field.options.map((option) => <option key={option} value={option}>{option}</option>)}</select> : <input className="input w-full" type={field.type === 'number' ? 'number' : 'text'} min={field.min} max={field.max} step={field.step} value={value ?? ''} onChange={(event) => onChange(event.target.value)} />}{field.description ? <span className="mt-1 block text-xs leading-5 text-dim">{field.description}</span> : null}</label>
}

export default function ConfigPage() {
  const [fields, setFields] = useState([])
  const [values, setValues] = useState({})
  const [env, setEnv] = useState({})
  const [savingConfig, setSavingConfig] = useState(false)
  const [savingEnv, setSavingEnv] = useState(false)

  const load = async () => {
    const res = await api.get('/api/config')
    const nextFields = res.data.config_fields || []
    setFields(nextFields)
    setValues(Object.fromEntries(nextFields.map((field) => [field.path, field.value ?? ''])))
    setEnv(res.data.env || {})
  }

  useEffect(() => { load() }, [])

  const provider = values['llm.provider'] || 'ollama'
  const visibleFields = useMemo(() => fields.filter((field) => !field.providers || field.providers.includes(provider)), [fields, provider])
  const sections = useMemo(() => {
    const grouped = new Map()
    visibleFields.forEach((field) => grouped.set(field.section, [...(grouped.get(field.section) || []), field]))
    return [...grouped.entries()]
  }, [visibleFields])
  const envEntries = useMemo(() => {
    const relevant = new Set(PROVIDER_ENV[provider] || [])
    return Object.entries(env).filter(([key, meta]) => !PROVIDER_ENV_KEYS.has(key) || relevant.has(key) || meta.set)
  }, [env, provider])

  const saveConfig = async () => {
    setSavingConfig(true)
    try {
      await api.put('/api/config/settings', { values })
      await load()
    } finally {
      setSavingConfig(false)
    }
  }

  const saveEnv = async () => {
    setSavingEnv(true)
    try {
      await api.put('/api/env', { values: Object.fromEntries(Object.entries(env).map(([key, meta]) => [key, meta.value])) })
      await load()
    } finally {
      setSavingEnv(false)
    }
  }

  const updateEnvValue = (key, value) => setEnv((current) => ({ ...current, [key]: { ...current[key], value } }))

  return (
    <div className="space-y-6">
      <PageHeader title="Config" subtitle="Configure supported runtime options without exposing internal YAML or unrelated provider settings." />
      <div className="grid items-start gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <section className="panel flex max-h-[calc(100vh-9rem)] flex-col overflow-hidden p-4">
          <div className="mb-4 flex items-start justify-between gap-4"><div><div className="font-mono text-xs uppercase tracking-[0.18em] text-cyan">Runtime configuration</div><div className="mt-1 text-sm text-dim">Validated options are saved to config.yaml; internal values remain untouched.</div></div><button className="btn btn-primary" onClick={saveConfig} disabled={savingConfig}>{savingConfig ? 'SAVING' : 'SAVE'}</button></div>
          <div className="min-h-0 flex-1 space-y-6 overflow-y-auto pr-2">
            {sections.map(([section, sectionFields]) => <fieldset key={section} className="rounded-xl border border-border bg-panel2 p-4"><legend className="px-2 font-mono text-xs uppercase tracking-[0.16em] text-cyan">{section}</legend><div className="grid gap-4 md:grid-cols-2">{sectionFields.map((field) => <RuntimeField key={field.path} field={field} value={values[field.path]} onChange={(value) => setValues((current) => ({ ...current, [field.path]: value }))} />)}</div></fieldset>)}
          </div>
        </section>

        <section className="panel flex max-h-[calc(100vh-9rem)] flex-col overflow-hidden p-4">
          <div className="mb-4 flex items-start justify-between gap-4"><div><div className="font-mono text-xs uppercase tracking-[0.18em] text-cyan">Environment</div><div className="mt-1 text-sm text-dim">Credentials and endpoints relevant to {provider}; configured secrets remain masked.</div></div><button className="btn btn-primary" onClick={saveEnv} disabled={savingEnv}>{savingEnv ? 'SAVING' : 'SAVE'}</button></div>
          <div className="min-h-0 flex-1 space-y-4 overflow-y-auto pr-1">
            {envEntries.length === 0 ? <div className="font-mono text-dim">No environment values are required.</div> : null}
            {envEntries.map(([key, meta]) => <label key={key} className="block"><span className="mb-1 block font-mono text-[11px] uppercase tracking-[0.16em] text-dim">{key}</span><input className="input w-full" type={meta.is_secret ? 'password' : 'text'} value={meta.value || ''} onChange={(event) => updateEnvValue(key, event.target.value)} placeholder={meta.is_secret ? '••••••••' : ''} /></label>)}
          </div>
        </section>
      </div>
    </div>
  )
}
