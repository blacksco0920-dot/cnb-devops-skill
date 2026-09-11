/** Read-only historical proof. The pinned bundle owns the production validators.
 * No operation here can sign, publish, invoke a command, or assert current runtime.
 */
import { parseStrictJson } from '../assets/cnb-tcr-tat/ci/strict-json.mjs';

export const DEPLOYMENT_FILES = ['candidate.json', 'readiness.json', 'approval.json', 'describe-commands.json',
  'describe-invocation-tasks.json', 'annotations-response.json', 'production-receipt.json'];
const requireValue = (value, code) => { if (!value) throw new Error(code); };
function parse(raw) {
  requireValue(Buffer.isBuffer(raw) && raw.length > 0 && raw.length <= 512 * 1024, 'DEPLOYMENT_EVIDENCE_INVALID');
  return parseStrictJson(new TextDecoder('utf-8', { fatal: true }).decode(raw), { maxBytes: 512 * 1024 });
}

export function deploymentEvidenceFiles({ candidateRaw, readinessRaw, approvalRaw, evidence }) {
  const tasks = parse(evidence['describe-invocation-tasks.json']);
  const output = tasks?.InvocationTaskSet?.[0]?.TaskResult?.Output;
  requireValue(typeof output === 'string' && output.length <= 128 * 1024, 'DEPLOYMENT_EVIDENCE_INVALID');
  return { 'candidate.json': candidateRaw, 'readiness.json': readinessRaw, 'approval.json': approvalRaw,
    'describe-commands.json': evidence['describe-commands.json'], 'describe-invocation-tasks.json': evidence['describe-invocation-tasks.json'],
    'annotations-response.json': evidence['annotations-response.json'], 'production-receipt.json': Buffer.from(output, 'base64') };
}

export async function verifyDeploymentEvidence(options) {
  const { contract, runner, tat, publisher, config, candidateConfig, binding, publicKey, candidateRaw, readinessRaw,
    approvalRaw, readinessInvocationId, invocationId, evidence, now = Date.now } = options;
  const candidate = contract.validateProductionContext(candidateRaw, candidateConfig, config);
  const readiness = contract.parseCanonical(readinessRaw), approval = contract.parseCanonical(approvalRaw);
  const approved = contract.verifyApproval(approval, publicKey);
  const commands = parse(evidence['describe-commands.json']), tasks = parse(evidence['describe-invocation-tasks.json']);
  const task = tasks?.InvocationTaskSet?.[0], start = contract.utc(task?.TaskResult?.ExecStartTime), end = contract.utc(task?.TaskResult?.ExecEndTime);
  const verifiedNow = now();
  requireValue(start <= end && end <= verifiedNow && Number.isFinite(verifiedNow), 'DEPLOYMENT_EXECUTION_WINDOW_INVALID');
  // Both endpoints must satisfy the unchanged authorization and prepared-state
  // lifetime. These actual TAT command timestamps never authorize another apply.
  const inputs = { candidateRaw, candidateConfig, config, binding, readiness, approval, publicKey };
  const operation = runner.productionOperation({ ...inputs, action: 'apply', now: start });
  contract.validateApprovedSelection(approval, publicKey, candidate, candidateRaw, readiness, config, end);
  const result = await tat.verifyTatInvocation({ ...inputs, ...operation, invocationId,
    client: { DescribeCommands: async () => commands, DescribeInvocationTasks: async () => tasks } });
  const rawReceipt = Buffer.from(task.TaskResult.Output, 'base64');
  // Preserve and require canonical production receipt bytes in addition to the
  // existing TAT transport and inner shared release validation.
  requireValue(contract.canonicalBytes(result.receipt).equals(rawReceipt), 'DEPLOYMENT_RECEIPT_ENCODING_INVALID');
  const plan = publisher.expectedApprovalAnnotations({ ...inputs, invocationId: readinessInvocationId, now: end });
  const rows = parse(evidence['annotations-response.json']), annotations = Object.create(null);
  requireValue(Array.isArray(rows) && rows.length <= 1024, 'DEPLOYMENT_ANNOTATIONS_INVALID');
  for (const item of rows) {
    requireValue(item && typeof item === 'object' && !Array.isArray(item) && typeof item.key === 'string'
      && typeof item.value === 'string' && !Object.hasOwn(annotations, item.key), 'DEPLOYMENT_ANNOTATIONS_INVALID');
    annotations[item.key] = item.value;
  }
  const receiptHash = contract.sha256(rawReceipt);
  for (const [key, value] of Object.entries({ ...plan.prerequisites, ...plan.payload, production_approval_status: 'signed',
    production_deploy_status: 'passed', production_receipt_sha256: receiptHash })) {
    requireValue(annotations[key] === value, 'DEPLOYMENT_ANNOTATIONS_MISMATCH');
  }
  const files = deploymentEvidenceFiles(options);
  return { schema: 'cnb-deployment-verification/v1', status: 'verified', project: config.project, environment: 'production',
    application_commit: candidate.application_commit, build_id: candidate.build_id, candidate_tag: candidate.candidate_tag,
    invocation_id: invocationId, verified_at: new Date(verifiedNow).toISOString(), images: candidate.services,
    verification_scope: 'historical_completed_deployment', current_runtime_verified: false,
    execution_started_at: task.TaskResult.ExecStartTime, execution_finished_at: task.TaskResult.ExecEndTime,
    region: binding.region, instance_id: binding.instance_id, command_id: binding.command_id,
    candidate_manifest_sha256: candidate.manifest_sha256, candidate_bytes_sha256: contract.sha256(candidateRaw),
    production_receipt_sha256: receiptHash, release_record_sha256: result.receipt.release_record_sha256,
    approval_id: approved.approval_id, approval_sha256: contract.sha256(approvalRaw),
    approval_issued_at: approved.issued_at, approval_expires_at: approved.expires_at,
    signature: 'verified_ed25519', signature_valid_across_execution: true, prepared_sha256: readiness.prepared_sha256,
    production_entry_sha256: config.production_entry_sha256, production_authority_sha256: config.production_authority_sha256,
    controller_program_sha256: config.controller_program_sha256, controller_compose_sha256: config.controller_compose_sha256,
    policy_sha256: config.policy_sha256, evidence_base: 'receipt_directory',
    evidence: DEPLOYMENT_FILES.map(path => ({ path, sha256: contract.sha256(files[path]) })) };
}
