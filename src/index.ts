// Public API for @aauth/praca. Consumers importing this package as a library
// (rather than running it as an MCP server via the bin) get the agent flow,
// the L1 store, the registry client, and the vocab adapter types.

export { invokeAtResource, invokeAtResourceComplete } from './agent.js'
export type {
  AgentSigningKey,
  Interaction,
  InteractionHandler,
  InvokeArgs,
  InvokeResult,
  PracaConfig,
} from './agent.js'

export { loadIdentity, loadBootstrapStatus, buildConfigFromLocalKeys } from './identity.js'
export type { BootstrapStatus } from './identity.js'

export { canonicalizeHost } from './host.js'
export type { CanonicalHost } from './host.js'

export { fetchResource, listOperationsForResource, getOperationsForResource, routeOperation, toL1Entry } from './resource.js'
export type { AAuthResourceMeta, FetchedResource, PickedVocab, RoutedOperation } from './resource.js'

export { fetchRegistry, readCachedRegistry, registryUrl } from './registry.js'
export type { RegistryEntry, RegistryIndex } from './registry.js'

export * as store from './store.js'
export type { AccessMode, L1Entry } from './store.js'

export * from './vocab/index.js'
