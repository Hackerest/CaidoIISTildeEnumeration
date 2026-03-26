import type { DefineAPI, SDK } from "caido:plugin";
import { type DedupeKey, type RequestResponse, RequestSpec } from "caido:utils";

const REPORTER = "IIS Tilde Enumeration";
const DEFAULT_METHODS = ["OPTIONS", "GET", "POST", "HEAD"];
const DEFAULT_SUFFIXES = [
  "/~1/.rem",
  "\\a.aspx",
  "/a.asp",
  "/a.aspx",
  "/a.ashx",
  "/a.jpg",
];
const DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_-";
const DEFAULT_NAME_MAX_LENGTH = 6;
const DEFAULT_EXTENSION_MAX_LENGTH = 3;
const DEFAULT_MAX_NUMERIC_SUFFIX = 3;
const DEFAULT_MAX_REQUESTS = 800;
const DEFAULT_CONCURRENCY = 20;
const MAX_STORED_JOBS = 50;

type Fingerprint = {
  status: number;
  length: number;
  bodyLength: number;
};

type ProbeEvidence = {
  label: string;
  requestId: string;
  method: string;
  path: string;
  status: number;
  length: number;
  roundtripMs: number;
};

type DetectionProfile = {
  method: string;
  suffix: string;
  positive: Fingerprint;
  negative: Fingerprint;
  evidence: ProbeEvidence[];
};

export type ScanOptions = {
  targetUrl: string;
  headers?: Array<{ name: string; value: string }>;
  methods?: string[];
  suffixes?: string[];
  charset?: string;
  nameMaxLength?: number;
  extensionMaxLength?: number;
  maxNumericSuffix?: number;
  maxRequests?: number;
  concurrency?: number;
  createFinding?: boolean;
  enumerateShortnames?: boolean;
};

export type EnumeratedEntry = {
  shortName: string;
  kind: "file" | "directory" | "partial";
  baseName: string;
  baseLength: number;
  extension?: string | undefined;
  extensionLength: number;
  numericSuffix: number;
  url: string;
};

export type ScanResult = {
  targetUrl: string;
  vulnerable: boolean;
  reason: string;
  requestsSent: number;
  detection?: DetectionProfile | undefined;
  entries: EnumeratedEntry[];
  findingCreated: boolean;
  errors: string[];
};

export type ScanJobStage =
  | "queued"
  | "detecting"
  | "enumerating-names"
  | "enumerating-extensions"
  | "confirming"
  | "creating-finding"
  | "cancelling"
  | "cancelled"
  | "completed"
  | "failed";

export type ScanJobStatus =
  | "queued"
  | "running"
  | "cancelled"
  | "completed"
  | "failed";

export type ScanJob = {
  id: string;
  targetUrl: string;
  status: ScanJobStatus;
  stage: ScanJobStage;
  message: string;
  requestsSent: number;
  maxRequests: number;
  discoveredCount: number;
  startedAt: string;
  updatedAt: string;
  finishedAt?: string | undefined;
  partialEntries: EnumeratedEntry[];
  result?: ScanResult | undefined;
};

type NormalizedOptions = {
  targetUrl: string;
  headers: Array<{ name: string; value: string }>;
  methods: string[];
  suffixes: string[];
  charset: string[];
  nameMaxLength: number;
  extensionMaxLength: number;
  maxNumericSuffix: number;
  maxRequests: number;
  concurrency: number;
  createFinding: boolean;
  enumerateShortnames: boolean;
};

type ParsedTarget = {
  scheme: "http" | "https";
  host: string;
  port: number;
  pathname: string;
};

type FileStatus = "no-file" | "file-found" | "more-files";

type ScanState = {
  requestsSent: number;
  discoveredCount: number;
  lastEmittedRequestCount: number;
  partialEntries: EnumeratedEntry[];
  statusCache: Map<string, Promise<boolean>>;
  onProgress: (
    update: Partial<
      Pick<
        ScanJob,
        | "stage"
        | "message"
        | "requestsSent"
        | "discoveredCount"
        | "partialEntries"
      >
    >,
  ) => void;
  shouldStop: () => boolean;
};

type Events = {
  scanUpdated: (job: ScanJob) => void;
};

class RequestBudgetExceeded extends Error {
  constructor(limit: number) {
    super(`Request budget exceeded (${limit})`);
    this.name = "RequestBudgetExceeded";
  }
}

class ScanCancelledError extends Error {
  constructor() {
    super("Scan cancelled");
    this.name = "ScanCancelledError";
  }
}

const jobs = new Map<string, ScanJob>();
const cancelledJobs = new Set<string>();

const isTerminalJob = (job: ScanJob) => {
  return (
    job.status === "cancelled" ||
    job.status === "completed" ||
    job.status === "failed"
  );
};

const clamp = (value: number, min: number, max: number) => {
  return Math.min(max, Math.max(min, value));
};

const nowIso = () => new Date().toISOString();

const randomToken = (length: number) => {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  let token = "";
  for (let index = 0; index < length; index += 1) {
    token += alphabet[Math.floor(Math.random() * alphabet.length)] ?? "x";
  }
  return token;
};

const createJobId = () => `${Date.now().toString(36)}-${randomToken(6)}`;

const parseTarget = (value: string): ParsedTarget => {
  const spec = new RequestSpec(value);
  return {
    scheme: spec.getTls() ? "https" : "http",
    host: spec.getHost(),
    port: spec.getPort(),
    pathname: spec.getPath() || "/",
  };
};

const buildTargetUrl = (target: ParsedTarget, path: string) => {
  const defaultPort = target.scheme === "https" ? 443 : 80;
  const port = target.port === defaultPort ? "" : `:${target.port}`;
  const normalizedPath =
    path.length === 0 ? "/" : path.startsWith("/") ? path : `/${path}`;
  return `${target.scheme}://${target.host}${port}${normalizedPath}`;
};

const normalizeUrl = (value: string) => {
  const target = parseTarget(value);
  return buildTargetUrl(target, target.pathname);
};

const uniqueStrings = (values: string[]) => {
  return [
    ...new Set(
      values.map((value) => value.trim()).filter((value) => value.length > 0),
    ),
  ];
};

const normalizeOptions = (input: ScanOptions): NormalizedOptions => {
  const methods = uniqueStrings(input.methods ?? DEFAULT_METHODS).map(
    (method) => method.toUpperCase(),
  );
  const suffixes = uniqueStrings(input.suffixes ?? DEFAULT_SUFFIXES);
  const charset = [
    ...new Set(
      (input.charset ?? DEFAULT_CHARSET)
        .split("")
        .filter((char) => char.length === 1),
    ),
  ];

  return {
    targetUrl: normalizeUrl(input.targetUrl),
    headers: (input.headers ?? []).filter(
      (header) => header.name.trim().length > 0,
    ),
    methods: methods.length > 0 ? methods : DEFAULT_METHODS,
    suffixes: suffixes.length > 0 ? suffixes : DEFAULT_SUFFIXES,
    charset: charset.length > 0 ? charset : DEFAULT_CHARSET.split(""),
    nameMaxLength: clamp(input.nameMaxLength ?? DEFAULT_NAME_MAX_LENGTH, 1, 6),
    extensionMaxLength: clamp(
      input.extensionMaxLength ?? DEFAULT_EXTENSION_MAX_LENGTH,
      0,
      3,
    ),
    maxNumericSuffix: clamp(
      input.maxNumericSuffix ?? DEFAULT_MAX_NUMERIC_SUFFIX,
      1,
      9,
    ),
    maxRequests: clamp(input.maxRequests ?? DEFAULT_MAX_REQUESTS, 50, 5000),
    concurrency: clamp(input.concurrency ?? DEFAULT_CONCURRENCY, 1, 32),
    createFinding: input.createFinding ?? true,
    enumerateShortnames: input.enumerateShortnames ?? false,
  };
};

const asyncPool = async <T, R>(
  items: T[],
  limit: number,
  task: (item: T) => Promise<R>,
): Promise<R[]> => {
  const results: R[] = new Array(items.length);
  let nextIndex = 0;

  const worker = async () => {
    while (nextIndex < items.length) {
      const currentIndex = nextIndex;
      nextIndex += 1;
      results[currentIndex] = await task(items[currentIndex] as T);
    }
  };

  const workers = Array.from({ length: Math.min(limit, items.length) }, () =>
    worker(),
  );
  for (const workerPromise of workers) {
    await workerPromise;
  }
  return results;
};

const getResponseBodyLength = (pair: RequestResponse) => {
  const body = pair.response.getBody();
  if (!body) {
    return 0;
  }

  return body.toRaw().length;
};

const fingerprintOf = (pair: RequestResponse): Fingerprint => {
  return {
    status: pair.response.getCode(),
    length: pair.response.getRaw().toBytes().length,
    bodyLength: getResponseBodyLength(pair),
  };
};

const fingerprintKey = (fingerprint: Fingerprint) => {
  return `${fingerprint.status}:${fingerprint.length}:${fingerprint.bodyLength}`;
};

const fingerprintsEqual = (left: Fingerprint, right: Fingerprint) => {
  return fingerprintKey(left) === fingerprintKey(right);
};

const joinPath = (basePath: string, suffix: string) => {
  const normalizedBase = basePath.endsWith("/")
    ? basePath.slice(0, -1)
    : basePath;
  const normalizedSuffix = suffix.startsWith("/") ? suffix : `/${suffix}`;
  return `${normalizedBase || ""}${normalizedSuffix}`;
};

const applyHeaders = (
  spec: RequestSpec,
  headers: Array<{ name: string; value: string }>,
) => {
  for (const header of headers) {
    spec.setHeader(header.name, header.value);
  }
};

const describeEntry = (entry: EnumeratedEntry) => {
  return entry.extension !== undefined
    ? `${entry.baseName}~${entry.numericSuffix}.${entry.extension}`
    : `${entry.baseName}~${entry.numericSuffix}`;
};

const createEntry = (
  options: NormalizedOptions,
  baseName: string,
  numericSuffix: number,
  extension: string | undefined,
): EnumeratedEntry => {
  const shortName =
    extension !== undefined
      ? `${baseName}~${numericSuffix}.${extension}`
      : `${baseName}~${numericSuffix}`;
  const target = parseTarget(options.targetUrl);

  return {
    shortName,
    kind: extension !== undefined ? "file" : "directory",
    baseName,
    baseLength: baseName.length,
    extension,
    extensionLength: extension?.length ?? 0,
    numericSuffix,
    url: buildTargetUrl(target, joinPath(target.pathname, shortName)),
  };
};

const createPartialBaseEntry = (
  options: NormalizedOptions,
  baseName: string,
): EnumeratedEntry => {
  const target = parseTarget(options.targetUrl);
  const shortName = `${baseName}*`;

  return {
    shortName,
    kind: "partial",
    baseName,
    baseLength: baseName.length,
    extension: undefined,
    extensionLength: 0,
    numericSuffix: 0,
    url: buildTargetUrl(target, joinPath(target.pathname, shortName)),
  };
};

const createPartialExtensionEntry = (
  options: NormalizedOptions,
  baseName: string,
  numericSuffix: number,
  extension: string,
): EnumeratedEntry => {
  const target = parseTarget(options.targetUrl);
  const shortName = `${baseName}~${numericSuffix}.${extension}*`;

  return {
    shortName,
    kind: "partial",
    baseName,
    baseLength: baseName.length,
    extension,
    extensionLength: extension.length,
    numericSuffix,
    url: buildTargetUrl(target, joinPath(target.pathname, shortName)),
  };
};

const isBasePartialEntry = (entry: EnumeratedEntry) => {
  return (
    entry.kind === "partial" &&
    entry.numericSuffix === 0 &&
    entry.extension === undefined
  );
};

const isExtensionPartialEntry = (entry: EnumeratedEntry) => {
  return (
    entry.kind === "partial" &&
    entry.numericSuffix > 0 &&
    entry.extension !== undefined
  );
};

const upsertStateEntry = (state: ScanState, entry: EnumeratedEntry) => {
  let nextEntries = [...state.partialEntries];

  if (isBasePartialEntry(entry)) {
    const hasMoreSpecific = nextEntries.some(
      (currentEntry) =>
        isBasePartialEntry(currentEntry) &&
        currentEntry.baseName.startsWith(entry.baseName) &&
        currentEntry.baseName.length > entry.baseName.length,
    );
    if (hasMoreSpecific) {
      return;
    }

    nextEntries = nextEntries.filter(
      (currentEntry) =>
        !(
          isBasePartialEntry(currentEntry) &&
          entry.baseName.startsWith(currentEntry.baseName)
        ),
    );
  }

  if (isExtensionPartialEntry(entry)) {
    const extension = entry.extension ?? "";
    const hasMoreSpecific = nextEntries.some(
      (currentEntry) =>
        isExtensionPartialEntry(currentEntry) &&
        currentEntry.baseName === entry.baseName &&
        currentEntry.numericSuffix === entry.numericSuffix &&
        (currentEntry.extension ?? "").startsWith(extension) &&
        (currentEntry.extension?.length ?? 0) > extension.length,
    );
    if (hasMoreSpecific) {
      return;
    }

    nextEntries = nextEntries.filter(
      (currentEntry) =>
        !(
          isExtensionPartialEntry(currentEntry) &&
          currentEntry.baseName === entry.baseName &&
          currentEntry.numericSuffix === entry.numericSuffix &&
          extension.startsWith(currentEntry.extension ?? "")
        ),
    );
  }

  if (entry.kind !== "partial") {
    nextEntries = nextEntries.filter(
      (currentEntry) =>
        !(
          currentEntry.kind === "partial" &&
          currentEntry.baseName === entry.baseName &&
          (currentEntry.numericSuffix === 0 ||
            currentEntry.numericSuffix === entry.numericSuffix)
        ),
    );
  }

  const key = `${entry.kind}:${entry.shortName}`;
  const next = new Map(
    nextEntries.map((currentEntry) => [
      `${currentEntry.kind}:${currentEntry.shortName}`,
      currentEntry,
    ]),
  );
  next.set(key, entry);
  state.partialEntries = [...next.values()];
  state.discoveredCount = state.partialEntries.filter(
    (currentEntry) => currentEntry.kind !== "partial",
  ).length;
};

const createProbeEvidence = (
  label: string,
  method: string,
  path: string,
  pair: RequestResponse,
): ProbeEvidence => {
  const fingerprint = fingerprintOf(pair);

  return {
    label,
    requestId: pair.request.getId(),
    method,
    path,
    status: fingerprint.status,
    length: fingerprint.length,
    roundtripMs: pair.response.getRoundtripTime(),
  };
};

const createProbeRequest = (
  targetUrl: string,
  method: string,
  path: string,
) => {
  const target = parseTarget(targetUrl);
  const spec = new RequestSpec(buildTargetUrl(target, path));
  spec.setMethod(method);
  return spec;
};

const sendProbe = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  method: string,
  path: string,
) => {
  if (state.shouldStop()) {
    throw new ScanCancelledError();
  }

  if (state.requestsSent >= options.maxRequests) {
    throw new RequestBudgetExceeded(options.maxRequests);
  }

  const spec = createProbeRequest(options.targetUrl, method, path);
  applyHeaders(spec, options.headers);
  state.requestsSent += 1;

  if (
    state.requestsSent === 1 ||
    state.requestsSent - state.lastEmittedRequestCount >= 10
  ) {
    state.lastEmittedRequestCount = state.requestsSent;
    state.onProgress({
      requestsSent: state.requestsSent,
      message: `Sent ${state.requestsSent} of ${options.maxRequests} requests`,
    });
  }

  return sdk.requests.send(spec);
};

const determineDetectionProfile = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
) => {
  const targetPath = parseTarget(options.targetUrl).pathname;
  state.onProgress({
    stage: "detecting",
    message:
      "Testing method and suffix combinations to find a stable IIS fingerprint",
  });

  for (const method of options.methods) {
    for (const suffix of options.suffixes) {
      const validPath = joinPath(targetPath, `*~1*${suffix}`);
      const invalidOnePath = joinPath(
        targetPath,
        `${randomToken(12)}*~1*${suffix}`,
      );
      const invalidTwoPath = joinPath(
        targetPath,
        `${randomToken(12)}*~1*${suffix}`,
      );

      state.onProgress({
        message: `Detection probe with ${method} ${suffix}`,
      });

      try {
        const valid = await sendProbe(sdk, options, state, method, validPath);
        const invalidOne = await sendProbe(
          sdk,
          options,
          state,
          method,
          invalidOnePath,
        );
        const invalidTwo = await sendProbe(
          sdk,
          options,
          state,
          method,
          invalidTwoPath,
        );

        const validFingerprint = fingerprintOf(valid);
        const invalidOneFingerprint = fingerprintOf(invalidOne);
        const invalidTwoFingerprint = fingerprintOf(invalidTwo);

        if (
          fingerprintsEqual(invalidOneFingerprint, invalidTwoFingerprint) &&
          !fingerprintsEqual(validFingerprint, invalidOneFingerprint)
        ) {
          state.onProgress({
            message: `Stable fingerprint identified with ${method} ${suffix}`,
          });

          return {
            method,
            suffix,
            positive: validFingerprint,
            negative: invalidOneFingerprint,
            evidence: [
              createProbeEvidence("valid", method, validPath, valid),
              createProbeEvidence(
                "invalid-a",
                method,
                invalidOnePath,
                invalidOne,
              ),
              createProbeEvidence(
                "invalid-b",
                method,
                invalidTwoPath,
                invalidTwo,
              ),
            ],
          } satisfies DetectionProfile;
        }
      } catch (error) {
        sdk.console.error(
          `Detection probe failed for ${method} ${suffix}: ${String(error)}`,
        );
      }
    }
  }

  return undefined;
};

const isPositive = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
  rawCandidate: string,
) => {
  const targetPath = parseTarget(options.targetUrl).pathname;
  const path = joinPath(targetPath, `${rawCandidate}${profile.suffix}`);
  const pair = await sendProbe(sdk, options, state, profile.method, path);
  return {
    matched: fingerprintsEqual(fingerprintOf(pair), profile.positive),
    pair,
    path,
  };
};

const getStatus = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
  rawCandidate: string,
): Promise<boolean> => {
  const cacheKey = rawCandidate;
  const cached = state.statusCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const pending = getStatusUncached(sdk, options, state, profile, rawCandidate);

  state.statusCache.set(cacheKey, pending);

  try {
    return await pending;
  } catch (error) {
    state.statusCache.delete(cacheKey);
    throw error;
  }
};

const getStatusUncached = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
  rawCandidate: string,
): Promise<boolean> => {
  const probe = await isPositive(sdk, options, state, profile, rawCandidate);
  const fingerprint = fingerprintOf(probe.pair);
  if (fingerprintsEqual(fingerprint, profile.negative)) {
    return false;
  }
  if (fingerprintsEqual(fingerprint, profile.positive)) {
    return true;
  }
  const retryProbe = await isPositive(
    sdk,
    options,
    state,
    profile,
    rawCandidate,
  );
  return !fingerprintsEqual(fingerprintOf(retryProbe.pair), profile.negative);
};

const getQuestionMarkSymbol = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
) => {
  if (await getStatus(sdk, options, state, profile, "?*~1*")) {
    return "?";
  }
  if (await getStatus(sdk, options, state, profile, ">*~1*")) {
    return ">";
  }
  return undefined;
};

const isLastFileName = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
  input: string,
  questionMarkSymbol: string | undefined,
): Promise<FileStatus> => {
  if (questionMarkSymbol === undefined) {
    return "more-files";
  }

  let result: FileStatus = "file-found";

  if (input.length < 6) {
    const hasMoreChars = await getStatus(
      sdk,
      options,
      state,
      profile,
      `${input}${questionMarkSymbol}*~1*`,
    );

    if (hasMoreChars) {
      result = "no-file";
      const exactName = await getStatus(
        sdk,
        options,
        state,
        profile,
        `${input}~1*`,
      );
      if (exactName) {
        result = "more-files";
      }
    } else {
      const exactName = await getStatus(
        sdk,
        options,
        state,
        profile,
        `${input}~1*`,
      );
      if (!exactName) {
        result = "no-file";
      }
    }
  }

  return result;
};

const isLastFileExt = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
  input: string,
): Promise<boolean> => {
  const ext = input.split(".")[1] ?? "";
  if (ext.length >= 3) {
    return true;
  }
  return !(await getStatus(sdk, options, state, profile, `${input}*`));
};

const isFolder = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
  input: string,
  questionMarkSymbol: string | undefined,
) => {
  if (questionMarkSymbol === undefined) {
    return true;
  }

  const targetPath = parseTarget(options.targetUrl).pathname;
  const questionPath = joinPath(
    targetPath,
    `${input}${questionMarkSymbol}${profile.suffix}`,
  );
  const starPath = joinPath(targetPath, `${input}*${profile.suffix}`);
  const questionProbe = await sendProbe(
    sdk,
    options,
    state,
    profile.method,
    questionPath,
  );
  const starProbe = await sendProbe(
    sdk,
    options,
    state,
    profile.method,
    starPath,
  );
  return fingerprintsEqual(
    fingerprintOf(questionProbe),
    fingerprintOf(starProbe),
  );
};

const buildNameScanList = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
) => {
  const values = await asyncPool(
    options.charset,
    options.concurrency,
    async (char) => {
      const valid = await getStatus(
        sdk,
        options,
        state,
        profile,
        `*${char}*~1*`,
      );
      if (!valid) {
        return null;
      }

      const invalid = await getStatus(
        sdk,
        options,
        state,
        profile,
        `${char.repeat(7)}*~1*`,
      );
      if (invalid) {
        const fallback = await getStatus(
          sdk,
          options,
          state,
          profile,
          `1234567890${char}*~1*`,
        );
        if (fallback) {
          return null;
        }
      }

      return char;
    },
  );

  return values.filter((value): value is string => value !== null);
};

const buildExtScanList = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
) => {
  const values = await asyncPool(
    options.charset,
    options.concurrency,
    async (char) => {
      const valid = await getStatus(
        sdk,
        options,
        state,
        profile,
        `*~1*${char}*`,
      );
      if (!valid) {
        return null;
      }

      const invalid = await getStatus(
        sdk,
        options,
        state,
        profile,
        `*~1*${char.repeat(4)}*`,
      );
      if (invalid) {
        const fallback = await getStatus(
          sdk,
          options,
          state,
          profile,
          `*~1.*${char}1234567890`,
        );
        if (fallback) {
          return null;
        }
      }

      return char;
    },
  );

  return values.filter((value): value is string => value !== null);
};

const enumerateNamePrefixes = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
  nameScanList: string[],
  questionMarkSymbol: string | undefined,
  prefix = "",
): Promise<string[]> => {
  const found = new Set<string>();

  if (state.shouldStop()) {
    throw new ScanCancelledError();
  }

  if (prefix.length === 0) {
    state.onProgress({
      stage: "enumerating-names",
      message: "Enumerating short-name prefixes",
    });
  }

  const results = await asyncPool(
    nameScanList,
    options.concurrency,
    async (char) => {
      const candidate = `${prefix}${char}`;
      if (
        !(await getStatus(sdk, options, state, profile, `${candidate}*~1*`))
      ) {
        return [];
      }

      state.onProgress({
        partialEntries: (() => {
          upsertStateEntry(state, createPartialBaseEntry(options, candidate));
          return state.partialEntries;
        })(),
        discoveredCount: state.discoveredCount,
        message: `Confirmed base prefix ${candidate}`,
      });

      const fileStatus = await isLastFileName(
        sdk,
        options,
        state,
        profile,
        candidate,
        questionMarkSymbol,
      );

      const matches: string[] = [];

      if (
        candidate.length < options.nameMaxLength &&
        fileStatus !== "file-found"
      ) {
        const nested = await enumerateNamePrefixes(
          sdk,
          options,
          state,
          profile,
          nameScanList,
          questionMarkSymbol,
          candidate,
        );
        matches.push(...nested);
      }

      if (fileStatus !== "no-file") {
        matches.push(candidate);
      }

      return matches;
    },
  );

  for (const values of results) {
    for (const value of values) {
      found.add(value);
    }
  }

  return [...found];
};

const enumerateExtensionPrefixes = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
  extScanList: string[],
  baseName: string,
  numericSuffix: number,
  prefix = "",
): Promise<string[]> => {
  const found = new Set<string>();

  if (state.shouldStop()) {
    throw new ScanCancelledError();
  }

  if (options.extensionMaxLength === 0) {
    return [];
  }

  if (prefix.length === 0) {
    state.onProgress({
      stage: "enumerating-extensions",
      message: `Enumerating extensions for ${baseName}`,
    });
  }

  const results = await asyncPool(
    extScanList,
    options.concurrency,
    async (char) => {
      const candidate = `${prefix}${char}`;
      if (
        !(await getStatus(
          sdk,
          options,
          state,
          profile,
          `${baseName}~${numericSuffix}.${candidate}*`,
        ))
      ) {
        return [];
      }

      const exactCandidate = `${baseName}~${numericSuffix}.${candidate}`;

      state.onProgress({
        partialEntries: (() => {
          upsertStateEntry(
            state,
            createPartialExtensionEntry(
              options,
              baseName,
              numericSuffix,
              candidate,
            ),
          );
          return state.partialEntries;
        })(),
        discoveredCount: state.discoveredCount,
        message: `Confirmed extension prefix ${baseName}~${numericSuffix}.${candidate}`,
      });

      const matches: string[] = [];

      if (candidate.length < options.extensionMaxLength) {
        const nested = await enumerateExtensionPrefixes(
          sdk,
          options,
          state,
          profile,
          extScanList,
          baseName,
          numericSuffix,
          candidate,
        );
        matches.push(...nested);
      }

      if (await isLastFileExt(sdk, options, state, profile, exactCandidate)) {
        matches.push(candidate);
      }

      return matches;
    },
  );

  for (const values of results) {
    for (const value of values) {
      found.add(value);
    }
  }

  return [...found];
};

const buildEntries = async (
  sdk: SDK,
  options: NormalizedOptions,
  state: ScanState,
  profile: DetectionProfile,
) => {
  const questionMarkSymbol = await getQuestionMarkSymbol(
    sdk,
    options,
    state,
    profile,
  );
  const nameScanList = await buildNameScanList(sdk, options, state, profile);
  const extScanList = await buildExtScanList(sdk, options, state, profile);

  state.onProgress({
    stage: "enumerating-names",
    message: `Prepared bruteforce alphabet (${nameScanList.length} name chars, ${extScanList.length} ext chars)`,
  });

  const baseNames = await enumerateNamePrefixes(
    sdk,
    options,
    state,
    profile,
    nameScanList,
    questionMarkSymbol,
  );
  const entries: EnumeratedEntry[] = [];
  const seen = new Set<string>();

  if (state.shouldStop()) {
    throw new ScanCancelledError();
  }

  state.onProgress({
    stage: "confirming",
    message: "Resolving numeric suffixes and extensions",
  });

  for (const baseName of baseNames.sort()) {
    const suffixes = Array.from(
      { length: options.maxNumericSuffix },
      (_, index) => index + 1,
    );
    const suffixResults = await asyncPool(
      suffixes,
      options.concurrency,
      async (numericSuffix) => {
        const withExtProbe = await isPositive(
          sdk,
          options,
          state,
          profile,
          `${baseName}~${numericSuffix}.*`,
        );
        const bareProbe = await isPositive(
          sdk,
          options,
          state,
          profile,
          `${baseName}~${numericSuffix}*`,
        );
        if (!withExtProbe.matched && !bareProbe.matched) {
          return [];
        }

        const resolvedEntries: EnumeratedEntry[] = [];

        if (bareProbe.matched) {
          if (
            await isFolder(
              sdk,
              options,
              state,
              profile,
              `${baseName}~${numericSuffix}`,
              questionMarkSymbol,
            )
          ) {
            const entry = createEntry(
              options,
              baseName,
              numericSuffix,
              undefined,
            );
            resolvedEntries.push(entry);
          }
        }

        if (withExtProbe.matched) {
          const extensions = await enumerateExtensionPrefixes(
            sdk,
            options,
            state,
            profile,
            extScanList,
            baseName,
            numericSuffix,
          );

          for (const extension of extensions.sort()) {
            const entry = createEntry(
              options,
              baseName,
              numericSuffix,
              extension,
            );
            resolvedEntries.push(entry);
          }
        }

        return resolvedEntries;
      },
    );

    for (const resolvedEntries of suffixResults) {
      for (const entry of resolvedEntries) {
        if (seen.has(entry.shortName)) {
          continue;
        }

        entries.push(entry);
        seen.add(entry.shortName);
        upsertStateEntry(state, entry);
        state.onProgress({
          discoveredCount: state.discoveredCount,
          partialEntries: state.partialEntries,
          message: `Confirmed ${entry.kind} ${entry.shortName}`,
        });
      }
    }
  }

  return entries;
};

const createFindingIfNeeded = async (
  sdk: SDK,
  options: NormalizedOptions,
  entries: EnumeratedEntry[],
  profile: DetectionProfile,
  state: ScanState,
) => {
  if (!options.createFinding) {
    return false;
  }

  if (state.shouldStop()) {
    throw new ScanCancelledError();
  }

  state.onProgress({
    stage: "creating-finding",
    message: "Creating Caido finding",
  });

  const evidence = profile.evidence[0];
  if (!evidence) {
    return false;
  }

  const evidenceRequest = await sdk.requests.get(evidence.requestId);
  const request = evidenceRequest?.request;
  if (!request) {
    return false;
  }

  const target = parseTarget(options.targetUrl);
  const origin = buildTargetUrl(target, "").replace(/\/$/, "");
  const dedupeKey = `${REPORTER}:${origin}:${target.pathname}` as DedupeKey;
  const names = entries.slice(0, 20).map(describeEntry);
  const truncated = entries.length > names.length ? "\n- ..." : "";

  await sdk.findings.create({
    title: "IIS short-name enumeration exposed",
    reporter: REPORTER,
    dedupeKey,
    request,
    description:
      `The target responded differently to wildcard 8.3 short-name probes, which indicates ` +
      `IIS short-name enumeration is likely enabled.\n\n` +
      `Detection method: ${profile.method}\n` +
      `Detection suffix: ${profile.suffix}\n` +
      `Enumerated candidates (${entries.length}):\n- ${names.join("\n- ")}${truncated}`,
  });

  return true;
};

const runScanJob = async (
  sdk: SDK<API, Events>,
  options: NormalizedOptions,
  initialJob: ScanJob,
) => {
  const errors: string[] = [];
  const jobId = initialJob.id;
  let detection: DetectionProfile | undefined;

  const updateJob = (patch: Partial<ScanJob>) => {
    const current = jobs.get(jobId);
    if (!current) {
      return;
    }

    const next: ScanJob = {
      ...current,
      ...patch,
      updatedAt: nowIso(),
    };
    jobs.set(jobId, next);
    sdk.api.send("scanUpdated", next);
  };

  const state: ScanState = {
    requestsSent: 0,
    discoveredCount: 0,
    lastEmittedRequestCount: 0,
    partialEntries: [],
    statusCache: new Map(),
    onProgress(update) {
      const current = jobs.get(jobId);
      if (
        !current ||
        isTerminalJob(current) ||
        current.stage === "cancelling"
      ) {
        return;
      }

      updateJob({
        ...update,
        status: "running",
        requestsSent: update.requestsSent ?? state.requestsSent,
        discoveredCount: update.discoveredCount ?? state.discoveredCount,
        partialEntries: update.partialEntries ?? state.partialEntries,
      });
    },
    shouldStop() {
      return cancelledJobs.has(jobId);
    },
  };

  try {
    updateJob({
      status: "running",
      stage: "detecting",
      message: "Starting scan",
    });

    detection = await determineDetectionProfile(sdk, options, state);
    if (!detection) {
      const result: ScanResult = {
        targetUrl: options.targetUrl,
        vulnerable: false,
        reason:
          "No stable IIS tilde fingerprint was identified with the configured methods and suffixes.",
        requestsSent: state.requestsSent,
        detection: undefined,
        entries: [],
        findingCreated: false,
        errors,
      };

      updateJob({
        status: "completed",
        stage: "completed",
        message: result.reason,
        requestsSent: state.requestsSent,
        discoveredCount: 0,
        finishedAt: nowIso(),
        result,
      });
      return;
    }

    if (!options.enumerateShortnames) {
      const result: ScanResult = {
        targetUrl: options.targetUrl,
        vulnerable: true,
        reason:
          "Stable IIS tilde fingerprint found. Shortname enumeration was disabled for this scan.",
        requestsSent: state.requestsSent,
        detection,
        entries: [...state.partialEntries],
        findingCreated: false,
        errors,
      };

      updateJob({
        status: "completed",
        stage: "completed",
        message: result.reason,
        requestsSent: state.requestsSent,
        discoveredCount: 0,
        finishedAt: nowIso(),
        result,
      });
      return;
    }

    const entries = await buildEntries(sdk, options, state, detection);
    const findingCreated = await createFindingIfNeeded(
      sdk,
      options,
      entries,
      detection,
      state,
    );

    const result: ScanResult = {
      targetUrl: options.targetUrl,
      vulnerable: true,
      reason:
        entries.length > 0
          ? "Stable short-name fingerprints found and candidate 8.3 shortnames enumerated."
          : "Stable short-name fingerprints found, but no concrete shortnames were confirmed within the configured budget.",
      requestsSent: state.requestsSent,
      detection,
      entries: [...state.partialEntries],
      findingCreated,
      errors,
    };

    updateJob({
      status: "completed",
      stage: "completed",
      message: result.reason,
      requestsSent: state.requestsSent,
      discoveredCount: entries.length,
      finishedAt: nowIso(),
      result,
    });
  } catch (error) {
    if (error instanceof ScanCancelledError) {
      const result: ScanResult = {
        targetUrl: options.targetUrl,
        vulnerable: false,
        reason:
          state.partialEntries.length > 0
            ? "Scan cancelled by user. Partial enumeration results are preserved."
            : "Scan cancelled by user.",
        requestsSent: state.requestsSent,
        detection,
        entries: [...state.partialEntries],
        findingCreated: false,
        errors: [],
      };

      updateJob({
        status: "cancelled",
        stage: "cancelled",
        message: "Scan cancelled",
        requestsSent: state.requestsSent,
        discoveredCount: state.discoveredCount,
        finishedAt: nowIso(),
        result,
      });
      cancelledJobs.delete(jobId);
      return;
    }

    const message = error instanceof Error ? error.message : String(error);

    if (error instanceof RequestBudgetExceeded) {
      const result: ScanResult = {
        targetUrl: options.targetUrl,
        vulnerable: detection !== undefined,
        reason:
          state.partialEntries.length > 0
            ? "Request budget exhausted. Partial enumeration results are shown."
            : "Request budget exhausted before enumeration completed.",
        requestsSent: state.requestsSent,
        detection,
        entries: [...state.partialEntries],
        findingCreated: false,
        errors: [message],
      };

      updateJob({
        status: "completed",
        stage: "completed",
        message: result.reason,
        requestsSent: state.requestsSent,
        discoveredCount: state.partialEntries.length,
        finishedAt: nowIso(),
        result,
      });
      return;
    }

    errors.push(message);

    const result: ScanResult = {
      targetUrl: options.targetUrl,
      vulnerable: false,
      reason: `Scan failed: ${message}`,
      requestsSent: state.requestsSent,
      detection,
      entries: [...state.partialEntries],
      findingCreated: false,
      errors,
    };

    updateJob({
      status: "failed",
      stage: "failed",
      message,
      requestsSent: state.requestsSent,
      discoveredCount: state.discoveredCount,
      finishedAt: nowIso(),
      result,
    });
  } finally {
    cancelledJobs.delete(jobId);
  }
};

const pruneJobs = () => {
  const allJobs = [...jobs.values()];
  if (allJobs.length <= MAX_STORED_JOBS) {
    return;
  }

  allJobs
    .sort((left, right) => left.updatedAt.localeCompare(right.updatedAt))
    .slice(0, allJobs.length - MAX_STORED_JOBS)
    .forEach((job) => {
      if (job.status !== "running") {
        jobs.delete(job.id);
      }
    });
};

const startScan = (sdk: SDK<API, Events>, rawOptions: ScanOptions): ScanJob => {
  const options = normalizeOptions(rawOptions);
  const job: ScanJob = {
    id: createJobId(),
    targetUrl: options.targetUrl,
    status: "queued",
    stage: "queued",
    message: "Queued",
    requestsSent: 0,
    maxRequests: options.maxRequests,
    discoveredCount: 0,
    startedAt: nowIso(),
    updatedAt: nowIso(),
    finishedAt: undefined,
    partialEntries: [],
    result: undefined,
  };

  jobs.set(job.id, job);
  pruneJobs();
  sdk.api.send("scanUpdated", job);
  void runScanJob(sdk, options, job);
  return job;
};

const listScans = () => {
  return [...jobs.values()].sort((left, right) =>
    right.startedAt.localeCompare(left.startedAt),
  );
};

const stopScan = (sdk: SDK<API, Events>, jobId: string) => {
  const job = jobs.get(jobId);
  if (!job) {
    return false;
  }

  if (job.status !== "queued" && job.status !== "running") {
    return false;
  }

  cancelledJobs.add(jobId);

  const next: ScanJob = {
    ...job,
    stage: "cancelling",
    message: "Cancellation requested",
    updatedAt: nowIso(),
  };
  jobs.set(jobId, next);
  sdk.api.send("scanUpdated", next);
  return true;
};

export type API = DefineAPI<{
  startScan: typeof startScan;
  listScans: typeof listScans;
  stopScan: typeof stopScan;
}>;

export type BackendEvents = Events;

export function init(sdk: SDK<API, Events>) {
  sdk.api.register("startScan", startScan);
  sdk.api.register("listScans", listScans);
  sdk.api.register("stopScan", stopScan);
}
