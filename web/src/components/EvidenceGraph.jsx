import { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { Box, Download, Focus, Maximize2, Minimize2, PanelRightClose, PanelRightOpen, Pencil, RotateCcw, Search, Tags, X } from 'lucide-react'
import SpriteText from 'three-spritetext'
import { api } from '../lib/api.js'

const ForceGraph3D = lazy(() => import('react-force-graph-3d'))

const COLORS = {
  host: '#67e8f9', skill: '#a3e635', process: '#c084fc', network: '#38bdf8',
  persistence: '#fb923c', file: '#facc15', package: '#94a3b8', service: '#2dd4bf',
  vulnerability: '#fb7185', control: '#4ade80', error: '#ef4444',
  neighbor: '#22d3ee', route: '#818cf8', interface: '#34d399', finding: '#f43f5e',
}
const SEVERITY_COLORS = { critical: '#dc2626', high: '#f97316', medium: '#facc15', low: '#38bdf8', info: '#94a3b8' }

function readGraphState(key) {
  try {
    const value = JSON.parse(localStorage.getItem(key) || 'null')
    return value && typeof value === 'object' ? value : null
  } catch {
    return null
  }
}

function evidenceFingerprint(value) {
  let hash = 2166136261
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index)
    hash = Math.imul(hash, 16777619)
  }
  return `${value.length}:${(hash >>> 0).toString(16)}`
}

function severityFromVulnerability(vulnerability) {
  return vulnerability.severity_label || 'unknown'
}

function nodeNarrative(node, parent, relation) {
  const evidence = node.evidence || {}
  const command = evidence.command || evidence.CommandLine || evidence.executable
  const address = evidence.remote || evidence.RemoteAddress || evidence.dst || evidence.IPAddress
  const version = evidence.version || evidence.installed_version
  const narratives = {
    host: ['A system participating in this investigation.', 'It anchors endpoint identity and the evidence collected from that system.', 'Unexpected identity, operating-system, or ownership changes can indicate asset drift or compromise.'],
    skill: ['A SecurityClaw capability that collected or analyzed evidence.', 'It records provenance so every finding can be traced to the tool that produced it.', 'Tool status and collection errors define coverage and must be considered before drawing conclusions.'],
    process: [`A running process${command ? ` observed as “${String(command).slice(0, 180)}”` : ''}.`, 'It was observed in the endpoint process inventory during this investigation.', 'Review its executable, owner, command line, parent process, and expected business purpose before treating it as trusted.'],
    network: [`An active network relationship${address ? ` involving ${address}` : ''}.`, 'It was reported by the local connection sensor and linked to the process or tool that observed it.', 'Unknown remote peers, unusual ports, unexpected listeners, or connections from privileged processes may require enrichment and containment review.'],
    persistence: ['An operating-system mechanism capable of starting software automatically.', 'It was found while inspecting scheduled tasks, services, startup entries, cron, or systemd configuration.', 'Persistence is legitimate for many applications, but unknown paths, unusual users, or recently changed entries are common investigation pivots.'],
    file: ['A file included in integrity monitoring with a cryptographic digest.', 'It was selected or observed during the endpoint integrity collection.', 'A digest change is evidence of modification, not proof of malware; validate signer, origin, timestamps, and expected deployment activity.'],
    package: [`Installed software${version ? ` at version ${version}` : ''}.`, 'It was discovered in the endpoint software inventory and can be correlated with published advisories.', 'Risk depends on the exact version, platform, exposure, vendor fixes, and whether a vulnerable component is reachable.'],
    service: ['An operating-system service or long-running system component.', 'It was discovered during service and defensive-posture inspection.', 'Review startup type, account privileges, executable path, listeners, and whether the service is expected on this host.'],
    vulnerability: ['A published advisory correlated with an observed installed package and version.', 'It is present because the vulnerability scanner found a grounded OSV match for endpoint software.', 'Severity describes potential impact; remediation priority must also consider exploitability, exposure, available fixes, and operational importance.'],
    control: ['A defensive configuration or security control checked on the endpoint.', 'It records the observed state of a posture assessment rather than an inferred result.', 'Missing or weakened controls increase attack surface, but the appropriate configuration depends on the host role and organizational policy.'],
    finding: ['A security-relevant observation produced by a passive or active defensive sensor.', 'It was added because a skill reported evidence that warrants analyst attention.', 'Validate the supporting evidence and surrounding timeline before escalating or taking containment action.'],
    neighbor: [`An ARP or NDP address-to-link-layer binding${address ? ` for ${address}` : ''}.`, 'It was collected from the endpoint neighbor cache during network-defense monitoring.', 'Binding changes can result from DHCP, failover, virtualization, or spoofing; gateway changes and corroborating traffic deserve higher priority.'],
    route: ['A route used by the endpoint to reach a network destination.', 'It was collected from the active routing table to establish network-path context.', 'Unexpected default gateways, interfaces, or recently changed routes can redirect or intercept traffic.'],
    interface: ['A local network interface and its observed operational state.', 'It provides the interface context for connections, neighbors, routes, and gateway evidence.', 'Unexpected interfaces, addresses, DNS settings, or state changes may indicate tunneling, virtualization, or configuration drift.'],
    error: ['A collection or analysis capability that reported an error.', 'It remains in the graph to make missing coverage explicit.', 'An error is not evidence that the host is safe; resolve the collection failure before relying on the assessment.'],
  }
  const [description, why, securityRelevance] = narratives[node.type] || ['Evidence collected during the investigation.', 'It was connected to the investigation by a runtime capability.', 'Interpret it together with its source, relationships, and collection coverage.']
  return { description, why, securityRelevance, provenance: { parent, relation } }
}

function evidenceSummary(evidence = {}) {
  const preferred = ['status', 'severity', 'pid', 'ppid', 'user', 'owner', 'command', 'executable', 'remote', 'local', 'state', 'protocol', 'version', 'installed_version', 'path', 'sha256', 'type']
  const entries = []
  preferred.forEach((key) => {
    const value = evidence[key]
    if (value !== undefined && value !== null && typeof value !== 'object') entries.push([key, String(value)])
  })
  return entries.slice(0, 10)
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function recordName(record, fallback) {
  if (!record || typeof record !== 'object') return fallback
  const source = record.src_ip || record.source_ip || record['source.ip'] || record.source?.ip
  const destination = record.dest_ip || record.destination_ip || record['destination.ip'] || record.destination?.ip
  const event = record.event_type || record.event?.action || record.action || record.type || record.verdict
  if (source || destination) return `${source || '?'} → ${destination || '?'}`
  return String(record.id || record.name || event || record['@timestamp'] || fallback)
}

function buildEvidenceGraph(skillResults = {}, annotations = {}) {
  const nodes = [{ id: 'host', name: 'Endpoint', type: 'host', description: 'Endpoint under defensive investigation.', evidence: {} }]
  const links = []
  const seen = new Set(['host'])
  const packageByName = new Map()
  const addNode = (node, parent = 'host', relation = 'OBSERVED_BY') => {
    if (!node.id || seen.has(node.id)) return
    seen.add(node.id)
    const annotation = annotations[node.id] || {}
    nodes.push({ ...node, ...nodeNarrative(node, parent, relation), name: annotation.name || node.name, analystSeverity: annotation.severity, notes: annotation.notes })
    links.push({ source: parent, target: node.id, type: relation })
  }

  Object.entries(skillResults).forEach(([skill, result]) => {
    if (!result || typeof result !== 'object') return
    const skillId = `skill:${skill}`
    addNode({ id: skillId, name: skill.replaceAll('_', ' '), type: result.status === 'error' ? 'error' : 'skill', description: `Runtime evidence produced by ${skill}.`, evidence: { status: result.status, errors: result.errors } }, 'host', 'EXECUTED')
    if (result.hostname) addNode({ id: `host:${result.hostname}`, name: result.hostname, type: 'host', description: result.os || 'Discovered endpoint identity.', evidence: result }, skillId, 'IDENTIFIED')
    ;asArray(result.processes).slice(0, 80).forEach((process) => addNode({ id: `process:${process.pid}`, name: `${process.name || 'process'} (${process.pid || '?'})`, type: 'process', description: process.command || process.executable || 'Running process.', evidence: process }, skillId, 'RUNNING'))
    ;asArray(result.connections).slice(0, 80).forEach((connection, index) => {
      const remote = connection.remote || `${connection.RemoteAddress || '?'}:${connection.RemotePort || '?'}`
      addNode({ id: `connection:${remote}:${index}`, name: remote, type: 'network', description: `${connection.protocol || 'TCP'} ${connection.state || connection.State || 'connection'}`, evidence: connection }, skillId, 'CONNECTED_TO')
    })
    ;asArray(result.persistence).slice(0, 60).forEach((entry, index) => {
      const name = entry.path || entry.TaskName || entry.type || `entry ${index + 1}`
      addNode({ id: `persistence:${name}:${index}`, name, type: 'persistence', description: 'Startup or persistence mechanism discovered on the endpoint.', evidence: entry }, skillId, 'PERSISTS_VIA')
    })
    ;asArray(result.files).slice(0, 60).forEach((file, index) => addNode({ id: `file:${file.path || index}`, name: file.path || `file ${index + 1}`, type: 'file', description: 'File integrity evidence with cryptographic digest.', evidence: file }, skillId, 'HASHED'))
    ;asArray(result.packages).slice(0, 120).forEach((pkg, index) => {
      const id = `package:${pkg.name}:${pkg.version}:${index}`
      packageByName.set(String(pkg.name || '').toLowerCase(), id)
      addNode({ id, name: `${pkg.name} ${pkg.version || ''}`.trim(), type: 'package', description: `${pkg.publisher || pkg.ecosystem || pkg.source || 'Installed software'} package.`, evidence: pkg }, skillId, 'INSTALLED')
    })
    ;asArray(result.services).slice(0, 80).forEach((service, index) => addNode({ id: `service:${service.name || service.Name}:${index}`, name: service.name || service.Name || `service ${index + 1}`, type: 'service', description: service.description || service.DisplayName || service.PathName || 'Operating-system service.', evidence: service }, skillId, 'HOSTS_SERVICE'))
    ;asArray(result.neighbors).slice(0, 120).forEach((neighbor, index) => {
      const ip = neighbor.dst || neighbor.IPAddress || `neighbor ${index + 1}`
      const mac = neighbor.lladdr || neighbor.LinkLayerAddress || 'unresolved'
      addNode({ id: `neighbor:${ip}:${mac}`, name: `${ip} · ${mac}`, type: 'neighbor', description: 'Observed ARP or NDP neighbor binding.', evidence: neighbor }, skillId, 'RESOLVES_TO')
    })
    ;asArray(result.routes).slice(0, 80).forEach((route, index) => addNode({ id: `route:${route.dst || route.DestinationPrefix}:${index}`, name: route.dst || route.DestinationPrefix || `route ${index + 1}`, type: 'route', description: `Route via ${route.gateway || route.NextHop || 'local interface'}.`, evidence: route }, skillId, 'ROUTES_VIA'))
    ;asArray(result.interfaces).slice(0, 40).forEach((item, index) => addNode({ id: `interface:${item.ifname || item.Name}:${index}`, name: item.ifname || item.Name || `interface ${index + 1}`, type: 'interface', description: item.InterfaceDescription || item.operstate || item.Status || 'Network interface.', evidence: item }, skillId, 'EXPOSES'))
    ;asArray(result.findings).slice(0, 100).forEach((finding, index) => addNode({ id: `finding:${skill}:${finding.type || 'finding'}:${index}`, name: String(finding.type || 'security finding').replaceAll('_', ' '), type: 'finding', severity: finding.severity || 'medium', description: finding.description || 'Passive security finding requiring investigation.', evidence: finding }, skillId, 'DETECTED'))
    ;['results', 'records', 'hits', 'alerts'].forEach((collection) => asArray(result[collection]).slice(0, 100).forEach((record, index) => addNode({ id: `finding:${skill}:${collection}:${index}`, name: recordName(record, `${collection.slice(0, -1)} ${index + 1}`), type: 'finding', severity: record.severity || 'info', evidence: record }, skillId, collection === 'alerts' ? 'ALERTED_ON' : 'OBSERVED')))
    ;asArray(result.timeline).slice(0, 100).forEach((event, index) => addNode({ id: `finding:${skill}:timeline:${index}`, name: recordName(event, `timeline event ${index + 1}`), type: 'finding', severity: event.severity || 'info', evidence: event }, skillId, 'OCCURRED'))
    ;asArray(result.verdicts).slice(0, 40).forEach((verdict, index) => addNode({ id: `finding:${skill}:verdict:${index}`, name: recordName(verdict, `verdict ${index + 1}`), type: 'finding', severity: verdict.verdict === 'TRUE_THREAT' ? 'high' : 'info', evidence: verdict }, skillId, 'ASSESSED'))
    ;asArray(result.lookups).slice(0, 40).forEach((lookup, index) => addNode({ id: `network:${skill}:lookup:${lookup.ip || index}`, name: lookup.ip || `network entity ${index + 1}`, type: 'network', severity: 'info', evidence: lookup }, skillId, 'ENRICHED'))
    Object.entries(result.checks || {}).forEach(([name, value]) => addNode({ id: `control:${name}`, name, type: 'control', description: 'Defensive posture check.', evidence: { value } }, skillId, 'CHECKED'))
    ;asArray(result.vulnerabilities).forEach((vulnerability, index) => {
      const id = vulnerability.id || vulnerability.cves?.[0] || `advisory-${index}`
      const affectedPackage = packageByName.get(String(vulnerability.package || '').toLowerCase())
      addNode({ id: `vulnerability:${id}:${index}`, name: vulnerability.cves?.[0] || id, type: 'vulnerability', severity: severityFromVulnerability(vulnerability), description: vulnerability.summary || 'Published vulnerability affecting installed software.', evidence: vulnerability }, affectedPackage || skillId, affectedPackage ? 'HAS_VULNERABILITY' : 'AFFECTED_BY')
    })
  })
  return { nodes, links }
}

export default function EvidenceGraph({ skillResults = {}, storageKey = 'current' }) {
  const graphStateKey = `securityclaw:graph-state:${storageKey}`
  const graph2DRef = useRef()
  const graph3DRef = useRef()
  const initialMeasurementRef = useRef(false)
  const previousNodeCountRef = useRef(0)
  const fittedRendererRef = useRef({ two: false, three: false })
  const stableGraphRef = useRef({ signature: '', graph: { nodes: [], links: [] } })
  const rendererGraphsRef = useRef({ two: { nodes: [], links: [] }, three: { nodes: [], links: [] } })
  const labelSpritesRef = useRef(new Map())
  const revealedNodeIdsRef = useRef(new Set(['host']))
  const enrichmentGenerationRef = useRef(0)
  const restoredGraphStateRef = useRef(null)
  const skipGraphPersistenceRef = useRef(null)
  const [mode3d, setMode3d] = useState(true)
  const [labels, setLabels] = useState(false)
  const [revealedNodeIds, setRevealedNodeIds] = useState(() => new Set(['host']))
  const [enrichments, setEnrichments] = useState({})
  const [enrichmentProgress, setEnrichmentProgress] = useState({ completed: 0, total: 0, active: false })
  const [query, setQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState('all')
  const [selected, setSelected] = useState(null)
  const [editing, setEditing] = useState(false)
  const [detailsOpen, setDetailsOpen] = useState(false)
  const [fullscreen, setFullscreen] = useState(false)
  const [wrapperElement, setWrapperElement] = useState(null)
  const [size, setSize] = useState({ width: 900, height: 620 })
  const annotationKey = `securityclaw:graph-annotations:${storageKey}`
  const [annotations, setAnnotations] = useState(() => {
    try { return JSON.parse(localStorage.getItem(annotationKey) || '{}') } catch { return {} }
  })
  useEffect(() => {
    if (!wrapperElement) return undefined
    const observer = new ResizeObserver(([entry]) => {
      const next = { width: Math.max(1, Math.floor(entry.contentRect.width)), height: Math.max(1, Math.floor(entry.contentRect.height)) }
      setSize((current) => current.width === next.width && current.height === next.height ? current : next)
    })
    observer.observe(wrapperElement)
    return () => observer.disconnect()
  }, [wrapperElement])

  useEffect(() => {
    if (!wrapperElement || initialMeasurementRef.current) return undefined
    initialMeasurementRef.current = true
    const timer = window.setTimeout(() => {
      graph2DRef.current?.zoomToFit?.(500, 60)
      graph3DRef.current?.zoomToFit?.(500, 60)
    }, 350)
    return () => window.clearTimeout(timer)
  }, [wrapperElement, size.width, size.height])
  useEffect(() => { localStorage.setItem(annotationKey, JSON.stringify(annotations)) }, [annotationKey, annotations])
  useEffect(() => {
    stableGraphRef.current = { signature: '', graph: { nodes: [], links: [] } }
    rendererGraphsRef.current = { two: { nodes: [], links: [] }, three: { nodes: [], links: [] } }
    labelSpritesRef.current.forEach((sprite) => sprite.dispose?.())
    labelSpritesRef.current.clear()
    revealedNodeIdsRef.current = new Set(['host'])
    setRevealedNodeIds(new Set(['host']))
    enrichmentGenerationRef.current += 1
    const restored = readGraphState(graphStateKey)
    restoredGraphStateRef.current = restored
    if (restored?.revealedNodeIds?.length) {
      revealedNodeIdsRef.current = new Set(restored.revealedNodeIds)
      revealedNodeIdsRef.current.add('host')
      setRevealedNodeIds(new Set(revealedNodeIdsRef.current))
    }
    setEnrichments(restored?.enrichments || {})
    setEnrichmentProgress({ completed: 0, total: 0, active: false })
    fittedRendererRef.current = { two: false, three: false }
    initialMeasurementRef.current = false
    previousNodeCountRef.current = 0
    setSelected(null)
    try { setAnnotations(JSON.parse(localStorage.getItem(annotationKey) || '{}')) } catch { setAnnotations({}) }
  }, [annotationKey, graphStateKey])

  const evidenceSignature = JSON.stringify({ skillResults, annotations })
  const currentEvidenceFingerprint = evidenceFingerprint(JSON.stringify(skillResults))
  const fullGraph = useMemo(() => {
    if (stableGraphRef.current.signature === evidenceSignature) return stableGraphRef.current.graph
    const next = buildEvidenceGraph(skillResults, annotations)
    const previousNodes = new Map(stableGraphRef.current.graph.nodes.map((node) => [node.id, node]))
    next.nodes = next.nodes.map((node) => {
      const previous = previousNodes.get(node.id)
      if (!previous) return node
      return {
        ...previous,
        ...node,
        x: previous.x,
        y: previous.y,
        z: previous.z,
        vx: previous.vx,
        vy: previous.vy,
        vz: previous.vz,
        fx: previous.fx,
        fy: previous.fy,
        fz: previous.fz,
      }
    })
    stableGraphRef.current = { signature: evidenceSignature, graph: next }
    return next
  }, [evidenceSignature])
  const enrichedGraph = useMemo(() => ({
    nodes: fullGraph.nodes.map((node) => ({ ...node, ...(enrichments[node.id] || {}) })),
    links: fullGraph.links,
  }), [fullGraph, enrichments])
  const types = useMemo(() => [...new Set(enrichedGraph.nodes.map((node) => node.type))].sort(), [enrichedGraph])
  useEffect(() => {
    if (fullGraph.nodes.length === 1) {
      setEnrichmentProgress({ completed: 0, total: 0, active: false })
      return undefined
    }
    const restored = restoredGraphStateRef.current
    const restoredMatches = restored?.evidenceFingerprint === currentEvidenceFingerprint
    if (restored && !restoredMatches) {
      restoredGraphStateRef.current = null
      skipGraphPersistenceRef.current = currentEvidenceFingerprint
      revealedNodeIdsRef.current = new Set(['host'])
      setRevealedNodeIds(new Set(['host']))
      setEnrichments({})
    }
    const available = new Set(fullGraph.nodes.map((node) => node.id))
    const retained = new Set([...revealedNodeIdsRef.current].filter((id) => available.has(id)))
    retained.add('host')
    revealedNodeIdsRef.current = retained
    setRevealedNodeIds(new Set(retained))
    const pending = fullGraph.nodes.filter((node) => !retained.has(node.id))
    const knownEnrichments = restoredMatches ? (restored.enrichments || {}) : enrichments
    const needsHostDescription = !knownEnrichments.host
    const candidates = needsHostDescription ? [fullGraph.nodes[0], ...pending] : pending
    if (!candidates.length) {
      setEnrichmentProgress({ completed: 0, total: 0, active: false })
      return undefined
    }

    const generation = ++enrichmentGenerationRef.current
    let cancelled = false
    setEnrichmentProgress({ completed: 0, total: candidates.length, active: true })
    const process = async () => {
      let completed = 0
      for (let cursor = 0; cursor < candidates.length; cursor += 20) {
        const batch = candidates.slice(cursor, cursor + 20)
        let nextEnrichments = {}
        try {
          const response = await api.post('/api/graph/enrich', {
            nodes: batch.map((node) => ({
              id: node.id,
              name: node.name,
              type: node.type,
              severity: node.severity,
              evidence: node.evidence,
              provenance: node.provenance,
            })),
          }, { timeout: 120000 })
          nextEnrichments = Object.fromEntries((response.data.items || []).map((item) => [item.id, item]))
        } catch {
          // Deterministic evidence narratives remain available when enrichment is offline.
        }
        if (cancelled || enrichmentGenerationRef.current !== generation) return
        if (Object.keys(nextEnrichments).length) {
          setEnrichments((current) => ({ ...current, ...nextEnrichments }))
          setSelected((current) => current && nextEnrichments[current.id] ? { ...current, ...nextEnrichments[current.id] } : current)
        }
        batch.forEach((node) => revealedNodeIdsRef.current.add(node.id))
        setRevealedNodeIds(new Set(revealedNodeIdsRef.current))
        completed += batch.length
        setEnrichmentProgress({ completed, total: candidates.length, active: completed < candidates.length })
        await new Promise((resolve) => window.setTimeout(resolve, 90))
      }
    }
    process()
    return () => { cancelled = true }
  }, [fullGraph])
  useEffect(() => {
    if (fullGraph.nodes.length === 1) return
    if (skipGraphPersistenceRef.current === currentEvidenceFingerprint) {
      skipGraphPersistenceRef.current = null
      return
    }
    const restored = restoredGraphStateRef.current
    if (restored?.evidenceFingerprint === currentEvidenceFingerprint) {
      const missingReveal = (restored.revealedNodeIds || []).some((id) => !revealedNodeIds.has(id))
      const missingEnrichment = Object.keys(restored.enrichments || {}).some((id) => !enrichments[id])
      if (missingReveal || missingEnrichment) return
    }
    localStorage.setItem(graphStateKey, JSON.stringify({
      evidenceFingerprint: currentEvidenceFingerprint,
      revealedNodeIds: [...revealedNodeIds],
      enrichments,
    }))
  }, [currentEvidenceFingerprint, enrichments, fullGraph.nodes.length, graphStateKey, revealedNodeIds])
  const graph = useMemo(() => {
    const needle = query.trim().toLowerCase()
    const visible = new Set(enrichedGraph.nodes.filter((node) => (typeFilter === 'all' || node.type === typeFilter || node.id === 'host') && (!needle || `${node.name} ${node.description} ${node.why} ${node.securityRelevance} ${JSON.stringify(node.evidence)}`.toLowerCase().includes(needle))).map((node) => node.id))
    if (needle || typeFilter !== 'all') visible.add('host')
    const nodes = enrichedGraph.nodes.filter((node) => visible.has(node.id) && revealedNodeIds.has(node.id)).map((node) => ({ ...node }))
    const links = enrichedGraph.links.filter((link) => {
      const source = typeof link.source === 'object' ? link.source.id : link.source
      const target = typeof link.target === 'object' ? link.target.id : link.target
      return visible.has(source) && visible.has(target) && revealedNodeIds.has(source) && revealedNodeIds.has(target)
    }).map((link) => ({ ...link, source: typeof link.source === 'object' ? link.source.id : link.source, target: typeof link.target === 'object' ? link.target.id : link.target }))
    return { nodes, links }
  }, [enrichedGraph, query, typeFilter, revealedNodeIds])
  const rendererGraphs = useMemo(() => {
    const updateRenderer = (rendererKey) => {
      const previousNodes = new Map(rendererGraphsRef.current[rendererKey].nodes.map((node) => [node.id, node]))
      const next = {
        nodes: graph.nodes.map((node) => {
          const previous = previousNodes.get(node.id)
          return previous ? { ...node, x: previous.x, y: previous.y, z: previous.z, vx: previous.vx, vy: previous.vy, vz: previous.vz, fx: previous.fx, fy: previous.fy, fz: previous.fz } : { ...node }
        }),
        links: graph.links.map((link) => ({
          ...link,
          source: typeof link.source === 'object' ? link.source.id : link.source,
          target: typeof link.target === 'object' ? link.target.id : link.target,
        })),
      }
      rendererGraphsRef.current[rendererKey] = next
      return next
    }
    return { two: updateRenderer('two'), three: updateRenderer('three') }
  }, [graph])

  const activeGraphRef = () => mode3d ? graph3DRef.current : graph2DRef.current

  useEffect(() => {
    const firstEvidence = previousNodeCountRef.current <= 1 && graph.nodes.length > 1
    previousNodeCountRef.current = graph.nodes.length
    if (!firstEvidence) return undefined
    const timer = window.setTimeout(() => {
      graph2DRef.current?.zoomToFit?.(600, 70)
      graph3DRef.current?.zoomToFit?.(600, 70)
    }, 350)
    return () => window.clearTimeout(timer)
  }, [graph.nodes.length])

  useEffect(() => {
    const timer = window.setTimeout(() => activeGraphRef()?.zoomToFit?.(500, 70), 250)
    return () => window.clearTimeout(timer)
  }, [mode3d])

  const nodeColor = (node) => SEVERITY_COLORS[node.analystSeverity || node.severity] || COLORS[node.type] || '#94a3b8'
  const nodeLabel = (node) => `${node.name}\n${node.type}${node.severity ? ` · ${node.severity}` : ''}\n${node.description}`
  const nodeThreeObject = (node) => {
    let sprite = labelSpritesRef.current.get(node.id)
    if (!sprite) {
      sprite = new SpriteText(node.name)
      sprite.textHeight = 3.5
      sprite.padding = 1.5
      sprite.borderRadius = 2
      sprite.backgroundColor = 'rgba(7, 13, 24, 0.82)'
      sprite.color = '#cbd5e1'
      sprite.position.y = 6
      labelSpritesRef.current.set(node.id, sprite)
    }
    if (sprite.text !== node.name) sprite.text = node.name
    sprite.visible = labels || selected?.id === node.id
    return sprite
  }

  useEffect(() => {
    const currentIds = new Set(rendererGraphs.three.nodes.map((node) => node.id))
    labelSpritesRef.current.forEach((sprite, id) => {
      if (!currentIds.has(id)) {
        sprite.dispose?.()
        labelSpritesRef.current.delete(id)
      } else {
        sprite.visible = labels || selected?.id === id
      }
    })
    graph3DRef.current?.refresh?.()
  }, [labels, selected?.id, rendererGraphs.three])
  const selectedRelationships = useMemo(() => {
    if (!selected) return []
    const names = new Map(enrichedGraph.nodes.map((node) => [node.id, node.name]))
    return enrichedGraph.links.flatMap((link) => {
      const source = typeof link.source === 'object' ? link.source.id : link.source
      const target = typeof link.target === 'object' ? link.target.id : link.target
      if (source !== selected.id && target !== selected.id) return []
      const peer = source === selected.id ? target : source
      return [{ direction: source === selected.id ? 'outbound' : 'inbound', relation: link.type, peer, peerName: names.get(peer) || peer }]
    })
  }, [enrichedGraph, selected])
  const focusNode = (node) => {
    setSelected(node)
    if (mode3d && node.x != null) {
      const distance = 110
      const ratio = 1 + distance / Math.hypot(node.x || 1, node.y || 1, node.z || 1)
      graph3DRef.current?.cameraPosition({ x: node.x * ratio, y: node.y * ratio, z: (node.z || 1) * ratio }, node, 900)
    } else {
      graph2DRef.current?.centerAt(node.x, node.y, 700)
      graph2DRef.current?.zoom(3.5, 700)
    }
  }
  const exportGraph = () => {
    const blob = new Blob([JSON.stringify({ ...enrichedGraph, annotations }, null, 2)], { type: 'application/json' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = 'securityclaw-evidence-graph.json'
    link.click()
    URL.revokeObjectURL(link.href)
  }
  const saveAnnotation = (form) => {
    const data = new FormData(form)
    setAnnotations((current) => ({ ...current, [selected.id]: { name: data.get('name'), severity: data.get('severity'), notes: data.get('notes') } }))
    setEditing(false)
  }
  const resetLayout = () => {
    const activeGraph = mode3d ? rendererGraphs.three : rendererGraphs.two
    activeGraph.nodes.forEach((node) => { node.fx = undefined; node.fy = undefined; node.fz = undefined })
    activeGraphRef()?.d3ReheatSimulation?.()
    window.setTimeout(() => activeGraphRef()?.zoomToFit?.(700, 60), 500)
  }

  if (fullGraph.nodes.length === 1) return <div className="p-6 text-sm text-dim">Run an endpoint investigation to generate an evidence graph.</div>
  const common = { width: size.width, height: size.height, nodeLabel, nodeColor, nodeVal: (node) => node.type === 'host' ? 8 : node.type === 'vulnerability' ? 6 : 3, linkLabel: (link) => link.type, linkColor: () => '#334155', linkDirectionalArrowLength: 4, linkDirectionalArrowRelPos: 1, onNodeClick: focusNode, backgroundColor: '#070d18', cooldownTicks: 120, cooldownTime: 4000, warmupTicks: 25, d3AlphaDecay: 0.06, d3VelocityDecay: 0.45 }

  return (
    <div className={`relative flex min-h-0 flex-1 overflow-hidden bg-[#070d18] ${fullscreen ? 'fixed inset-0 z-50' : ''}`}>
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <div className="relative min-w-56 flex-1"><Search className="absolute left-3 top-2.5 h-4 w-4 text-dim" /><input className="input w-full pl-9" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search nodes, evidence or CVE…" /></div>
          <select className="input" value={typeFilter} onChange={(event) => setTypeFilter(event.target.value)}><option value="all">All node types</option>{types.map((type) => <option key={type}>{type}</option>)}</select>
          <button className={`btn ${mode3d ? 'btn-primary' : ''}`} onClick={() => setMode3d((value) => !value)}><Box className="h-4 w-4" /> {mode3d ? '3D' : '2D'}</button>
          <button className={`btn ${labels ? 'btn-primary' : ''}`} onClick={() => setLabels((value) => !value)}><Tags className="h-4 w-4" /> Labels</button>
          <button className="btn" onClick={() => activeGraphRef()?.zoomToFit?.(700, 50)}><Focus className="h-4 w-4" /> Fit</button>
          <button className="btn" onClick={resetLayout}><RotateCcw className="h-4 w-4" /> Reset</button>
          <button className="btn" onClick={() => setDetailsOpen((value) => !value)}>{detailsOpen ? <PanelRightClose className="h-4 w-4" /> : <PanelRightOpen className="h-4 w-4" />} Details</button>
          <button className="btn" onClick={() => setFullscreen((value) => !value)}>{fullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />} {fullscreen ? 'Exit' : 'Expand'}</button>
          <button className="btn" onClick={exportGraph}><Download className="h-4 w-4" /> JSON</button>
          {enrichmentProgress.active ? <span className="badge badge-green">Analyzing {enrichmentProgress.completed}/{enrichmentProgress.total}</span> : null}
        </div>
        <div ref={setWrapperElement} className="relative min-h-[520px] flex-1 overflow-hidden">
          <div className={`absolute inset-0 ${mode3d ? 'visible pointer-events-auto' : 'invisible pointer-events-none'}`} aria-hidden={!mode3d}>
            <Suspense fallback={<div className="p-6 text-sm text-dim">Loading 3D renderer…</div>}><ForceGraph3D ref={graph3DRef} {...common} graphData={rendererGraphs.three} nodeThreeObject={nodeThreeObject} nodeThreeObjectExtend onNodeDragEnd={(node) => { node.fx = node.x; node.fy = node.y; node.fz = node.z }} onEngineStop={() => { const controls = graph3DRef.current?.controls?.(); if (controls) controls.autoRotate = false; if (!fittedRendererRef.current.three) { fittedRendererRef.current.three = true; graph3DRef.current?.zoomToFit?.(600, 70) } }} /></Suspense>
          </div>
          <div className={`absolute inset-0 ${mode3d ? 'invisible pointer-events-none' : 'visible pointer-events-auto'}`} aria-hidden={mode3d}>
            <ForceGraph2D ref={graph2DRef} {...common} graphData={rendererGraphs.two} onNodeDragEnd={(node) => { node.fx = node.x; node.fy = node.y }} nodeCanvasObjectMode={() => 'after'} nodeCanvasObject={(node, context, scale) => { if (!labels && rendererGraphs.two.nodes.length > 24 && selected?.id !== node.id) return; context.font = `${Math.max(10 / scale, 2)}px sans-serif`; context.fillStyle = '#cbd5e1'; context.textAlign = 'center'; context.fillText(node.name.slice(0, 34), node.x, node.y + 8) }} />
          </div>
        </div>
      </div>
      {detailsOpen ? <aside className="absolute inset-y-0 right-0 z-20 w-80 overflow-auto border-l border-border bg-panel2/95 p-4 shadow-2xl backdrop-blur">
        <div className="mb-4 flex items-center justify-between border-b border-border pb-3"><span className="font-mono text-[11px] uppercase tracking-[0.16em] text-cyan">Node details</span><button className="btn" type="button" onClick={() => setDetailsOpen(false)} aria-label="Close node details"><X className="h-4 w-4" /> Close</button></div>
        {!selected ? <div className="text-sm text-dim">Select a node to inspect its evidence and add analyst annotations.</div> : <>
          <div className="flex items-start justify-between gap-2"><div><span className="badge badge-green">{selected.type}</span><h3 className="mt-2 break-words text-lg font-semibold text-text">{selected.name}</h3></div><button className="btn" onClick={() => setEditing((value) => !value)} aria-label="Edit node annotation"><Pencil className="h-4 w-4" /></button></div>
          <section className="mt-4 space-y-3 text-sm"><div><div className="font-mono text-[10px] uppercase tracking-wider text-cyan">What it is</div><p className="mt-1 text-text">{selected.description}</p></div><div><div className="font-mono text-[10px] uppercase tracking-wider text-cyan">Why it is here</div><p className="mt-1 text-dim">{selected.why}</p></div><div><div className="font-mono text-[10px] uppercase tracking-wider text-cyan">Security relevance</div><p className="mt-1 text-dim">{selected.securityRelevance}</p></div></section>
          {selected.enrichmentSources?.length ? <div className="mt-4"><div className="font-mono text-[10px] uppercase tracking-wider text-dim">Analysis sources</div><div className="mt-2 flex flex-wrap gap-2">{selected.enrichmentSources.map((source) => <span key={source} className="badge badge-green">{source}</span>)}</div></div> : null}
          {editing ? <form className="mt-4 space-y-3" onSubmit={(event) => { event.preventDefault(); saveAnnotation(event.currentTarget) }}><input className="input w-full" name="name" defaultValue={selected.name} /><select className="input w-full" name="severity" defaultValue={selected.analystSeverity || selected.severity || 'info'}>{['critical', 'high', 'medium', 'low', 'info'].map((value) => <option key={value}>{value}</option>)}</select><textarea className="input min-h-28 w-full" name="notes" defaultValue={selected.notes || ''} placeholder="Analyst notes" /><button className="btn btn-primary" type="submit">Save annotation</button></form> : null}
          {selected.notes ? <div className="mt-4 rounded-lg border border-cyan/20 bg-cyan/5 p-3 text-sm text-text"><div className="mb-1 font-mono text-[10px] uppercase text-cyan">Analyst notes</div>{selected.notes}</div> : null}
          {evidenceSummary(selected.evidence).length ? <div className="mt-4"><div className="font-mono text-[10px] uppercase tracking-wider text-dim">Evidence summary</div><dl className="mt-2 divide-y divide-border rounded-lg border border-border">{evidenceSummary(selected.evidence).map(([key, value]) => <div key={key} className="grid grid-cols-[100px_1fr] gap-2 p-2 text-xs"><dt className="font-mono text-cyan">{key}</dt><dd className="break-words text-text">{value}</dd></div>)}</dl></div> : null}
          {selectedRelationships.length ? <div className="mt-4"><div className="font-mono text-[10px] uppercase tracking-wider text-dim">Graph relationships</div><div className="mt-2 space-y-2">{selectedRelationships.slice(0, 20).map((item, index) => <div key={`${item.peer}-${index}`} className="rounded-lg border border-border p-2 text-xs"><span className="text-cyan">{item.relation}</span><span className="ml-2 text-text">{item.peerName}</span><span className="ml-2 text-dim">{item.direction}</span></div>)}</div></div> : null}
          <details className="mt-4"><summary className="cursor-pointer font-mono text-[10px] uppercase tracking-wider text-dim">Raw technical evidence</summary><pre className="mt-2 max-h-[360px] overflow-auto whitespace-pre-wrap break-all rounded-lg bg-black/30 p-3 text-xs text-dim">{JSON.stringify(selected.evidence, null, 2)}</pre></details>
        </>}
      </aside> : null}
    </div>
  )
}
