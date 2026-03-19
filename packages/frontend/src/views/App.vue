<script setup lang="ts">
import type { ScanJob, ScanOptions } from "backend";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";

import { useSDK } from "@/plugins/sdk";

const sdk = useSDK();

const targetUrl = ref("");
const headersText = ref("");
const methodsText = ref("OPTIONS\nGET\nPOST\nHEAD");
const suffixesText = ref(
  "/~1/.rem\n\\a.aspx\n/a.asp\n/a.aspx\n/a.ashx\n/a.jpg",
);
const charset = ref("abcdefghijklmnopqrstuvwxyz0123456789_-");
const nameMaxLength = ref(6);
const extensionMaxLength = ref(3);
const maxNumericSuffix = ref(3);
const maxRequests = ref(2000);
const concurrency = ref(20);
const createFinding = ref(true);
const enumerateShortnames = ref(false);

const isStarting = ref(false);
const error = ref("");
const jobs = ref<ScanJob[]>([]);

const parseLines = (value: string) => {
  return value
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
};

const parseHeaders = (value: string): ScanOptions["headers"] => {
  return parseLines(value)
    .map((line) => {
      const separator = line.indexOf(":");
      if (separator === -1) {
        return null;
      }

      return {
        name: line.slice(0, separator).trim(),
        value: line.slice(separator + 1).trim(),
      };
    })
    .filter((header): header is NonNullable<ScanOptions["headers"]>[number] => {
      return Boolean(header?.name);
    });
};

const sortJobs = (entries: ScanJob[]) => {
  return [...entries].sort((left, right) =>
    right.startedAt.localeCompare(left.startedAt),
  );
};

const upsertJob = (job: ScanJob) => {
  const next = [...jobs.value];
  const index = next.findIndex((entry) => entry.id === job.id);
  if (index === -1) {
    next.unshift(job);
  } else {
    next.splice(index, 1, job);
  }
  jobs.value = sortJobs(next);
};

const activeJobs = computed(() =>
  jobs.value.filter(
    (job) => job.status === "running" || job.status === "queued",
  ),
);

const canSubmit = computed(
  () => targetUrl.value.trim().length > 0 && !isStarting.value,
);

const queueLabel = (job: ScanJob) => {
  if (job.status === "queued") {
    return job.stage === "cancelling" ? "Cancelling" : "Queued";
  }
  if (job.status === "running") {
    if (job.stage === "cancelling") {
      return "Cancelling";
    }
    return `Running: ${job.stage}`;
  }
  if (job.status === "cancelled") {
    return "Cancelled";
  }
  if (job.status === "failed") {
    return "Failed";
  }
  return "Completed";
};

const requestProgress = (job: ScanJob) => {
  const percent = Math.min(
    100,
    Math.round((job.requestsSent / job.maxRequests) * 100),
  );
  return Number.isFinite(percent) ? percent : 0;
};

const isStoppable = (job: ScanJob) =>
  job.finishedAt === undefined &&
  job.stage !== "cancelling" &&
  job.status !== "cancelled" &&
  job.status !== "completed" &&
  job.status !== "failed";

const showProgressBar = (job: ScanJob) =>
  job.finishedAt === undefined &&
  job.status !== "cancelled" &&
  job.status !== "completed" &&
  job.status !== "failed";

const visibleEntries = (job: ScanJob) => {
  const merged = [...(job.result?.entries ?? []), ...job.partialEntries];
  const deduped = new Map(
    merged.map((entry) => [`${entry.kind}:${entry.shortName}`, entry]),
  );

  return [...deduped.values()].sort((left, right) =>
    left.shortName.localeCompare(right.shortName),
  );
};

const onSubmit = async () => {
  isStarting.value = true;
  error.value = "";

  try {
    const job = await sdk.backend.startScan({
      targetUrl: targetUrl.value.trim(),
      headers: parseHeaders(headersText.value),
      methods: parseLines(methodsText.value),
      suffixes: parseLines(suffixesText.value),
      charset: charset.value,
      nameMaxLength: nameMaxLength.value,
      extensionMaxLength: extensionMaxLength.value,
      maxNumericSuffix: maxNumericSuffix.value,
      maxRequests: maxRequests.value,
      concurrency: concurrency.value,
      createFinding: createFinding.value,
      enumerateShortnames: enumerateShortnames.value,
    });
    upsertJob(job);
  } catch (caught) {
    error.value = caught instanceof Error ? caught.message : String(caught);
  } finally {
    isStarting.value = false;
  }
};

const refreshJobs = async () => {
  jobs.value = sortJobs(await sdk.backend.listScans());
};

const stopJob = async (jobId: string) => {
  error.value = "";
  try {
    await sdk.backend.stopScan(jobId);
  } catch (caught) {
    error.value = caught instanceof Error ? caught.message : String(caught);
  }
};

let subscription: { stop: () => void } | undefined;

onMounted(async () => {
  await refreshJobs();
  subscription = sdk.backend.onEvent("scanUpdated", (job) => {
    upsertJob(job);
  });
});

onBeforeUnmount(() => {
  subscription?.stop();
});
</script>

<template>
  <div
    class="h-full min-h-full w-full overflow-auto bg-surface-0 text-surface-950 dark:bg-surface-900 dark:text-surface-0"
  >
    <div class="flex min-h-full w-full flex-col gap-4 p-4 lg:p-5">
      <div
        class="rounded-md border border-surface-200 bg-surface-50 p-4 dark:border-surface-700 dark:bg-surface-800"
      >
        <h1 class="text-lg font-semibold">IIS Tilde Enumeration</h1>
        <p class="mt-1 text-sm text-surface-600 dark:text-surface-300">
          Launch multiple IIS 8.3 short-name scans and follow their progress
          while they run in the background.
        </p>
        <p
          v-if="activeJobs.length > 0"
          class="mt-2 text-xs text-surface-500 dark:text-surface-400"
        >
          {{ activeJobs.length }} scan{{ activeJobs.length === 1 ? "" : "s" }}
          currently active.
        </p>
      </div>

      <div
        class="grid min-h-0 flex-1 gap-4 2xl:grid-cols-[minmax(22rem,28rem)_minmax(0,1fr)]"
      >
        <form
          class="h-fit rounded-md border border-surface-200 bg-surface-50 p-4 dark:border-surface-700 dark:bg-surface-800 2xl:sticky 2xl:top-4"
          @submit.prevent="onSubmit"
        >
          <div class="grid gap-4">
            <label class="grid gap-1.5">
              <span class="text-sm font-medium">Target URL</span>
              <input
                v-model="targetUrl"
                class="rounded-md border border-surface-300 bg-surface-0 px-3 py-2 text-sm outline-none dark:border-surface-600 dark:bg-surface-900"
                placeholder="https://target.tld/app/"
                type="url"
              />
            </label>

            <div class="grid gap-4 lg:grid-cols-2 2xl:grid-cols-1">
              <label class="grid gap-1.5">
                <span class="text-sm font-medium">Methods</span>
                <textarea
                  v-model="methodsText"
                  class="min-h-28 rounded-md border border-surface-300 bg-surface-0 px-3 py-2 font-mono text-sm outline-none dark:border-surface-600 dark:bg-surface-900"
                />
              </label>

              <label class="grid gap-1.5">
                <span class="text-sm font-medium">Suffixes</span>
                <textarea
                  v-model="suffixesText"
                  class="min-h-28 rounded-md border border-surface-300 bg-surface-0 px-3 py-2 font-mono text-sm outline-none dark:border-surface-600 dark:bg-surface-900"
                />
              </label>
            </div>

            <label class="grid gap-1.5">
              <span class="text-sm font-medium">Headers</span>
              <textarea
                v-model="headersText"
                class="min-h-24 rounded-md border border-surface-300 bg-surface-0 px-3 py-2 font-mono text-sm outline-none dark:border-surface-600 dark:bg-surface-900"
                placeholder="Cookie: session=..."
              />
            </label>

            <div
              class="grid gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-1"
            >
              <label class="grid gap-1.5">
                <span class="text-sm font-medium">Charset</span>
                <input
                  v-model="charset"
                  class="rounded-md border border-surface-300 bg-surface-0 px-3 py-2 font-mono text-sm outline-none dark:border-surface-600 dark:bg-surface-900"
                />
              </label>

              <label class="grid gap-1.5">
                <span class="text-sm font-medium">Request budget</span>
                <input
                  v-model.number="maxRequests"
                  class="rounded-md border border-surface-300 bg-surface-0 px-3 py-2 text-sm outline-none dark:border-surface-600 dark:bg-surface-900"
                  min="50"
                  max="5000"
                  step="50"
                  type="number"
                />
              </label>

              <label class="grid gap-1.5">
                <span class="text-sm font-medium">Concurrency</span>
                <input
                  v-model.number="concurrency"
                  class="rounded-md border border-surface-300 bg-surface-0 px-3 py-2 text-sm outline-none dark:border-surface-600 dark:bg-surface-900"
                  min="1"
                  max="32"
                  type="number"
                />
              </label>
            </div>

            <div
              class="grid gap-4 sm:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-1"
            >
              <label class="grid gap-1.5">
                <span class="text-sm font-medium">Name max</span>
                <input
                  v-model.number="nameMaxLength"
                  class="rounded-md border border-surface-300 bg-surface-0 px-3 py-2 text-sm outline-none dark:border-surface-600 dark:bg-surface-900"
                  min="1"
                  max="6"
                  type="number"
                />
              </label>

              <label class="grid gap-1.5">
                <span class="text-sm font-medium">Ext max</span>
                <input
                  v-model.number="extensionMaxLength"
                  class="rounded-md border border-surface-300 bg-surface-0 px-3 py-2 text-sm outline-none dark:border-surface-600 dark:bg-surface-900"
                  min="0"
                  max="3"
                  type="number"
                />
              </label>

              <label class="grid gap-1.5">
                <span class="text-sm font-medium">Max numeric suffix</span>
                <input
                  v-model.number="maxNumericSuffix"
                  class="rounded-md border border-surface-300 bg-surface-0 px-3 py-2 text-sm outline-none dark:border-surface-600 dark:bg-surface-900"
                  min="1"
                  max="9"
                  type="number"
                />
              </label>
            </div>

            <div class="grid gap-3 sm:grid-cols-2 2xl:grid-cols-1">
              <label class="flex items-center gap-2 text-sm">
                <input
                  v-model="createFinding"
                  type="checkbox"
                  class="h-4 w-4 shrink-0"
                />
                Create finding
              </label>

              <label class="flex items-center gap-2 text-sm">
                <input
                  v-model="enumerateShortnames"
                  type="checkbox"
                  class="h-4 w-4 shrink-0"
                />
                Enumerate shortnames after detection
              </label>
            </div>

            <div
              v-if="error"
              class="rounded-md border border-red-300 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-800 dark:bg-red-950/40 dark:text-red-200"
            >
              {{ error }}
            </div>

            <div
              class="flex flex-col gap-2 sm:flex-row sm:items-center sm:gap-3"
            >
              <button
                :disabled="!canSubmit"
                class="rounded-md border border-surface-300 bg-surface-0 px-4 py-2 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-50 dark:border-surface-600 dark:bg-surface-900"
                type="submit"
              >
                {{ isStarting ? "Starting..." : "Start scan" }}
              </button>
              <span
                class="text-xs leading-5 text-surface-500 dark:text-surface-400"
              >
                Detection-only scans finish quickly. Enable enumeration only
                when you want the longer brute-force phase.
              </span>
            </div>
          </div>
        </form>

        <section
          class="min-h-0 rounded-md border border-surface-200 bg-surface-50 p-4 dark:border-surface-700 dark:bg-surface-800"
        >
          <div class="mb-3 flex flex-wrap items-center justify-between gap-2">
            <h2 class="text-sm font-semibold">Scan Jobs</h2>
            <button
              class="rounded-md border border-surface-300 bg-surface-0 px-3 py-1.5 text-xs dark:border-surface-600 dark:bg-surface-900"
              type="button"
              @click="refreshJobs"
            >
              Refresh
            </button>
          </div>

          <div
            v-if="jobs.length === 0"
            class="flex min-h-64 items-center justify-center rounded-md border border-dashed border-surface-300 px-4 text-center text-sm text-surface-500 dark:border-surface-600 dark:text-surface-400"
          >
            No scans started yet.
          </div>

          <div v-else class="grid gap-3">
            <article
              v-for="job in jobs"
              :key="job.id"
              class="rounded-md border border-surface-200 p-3 dark:border-surface-700"
            >
              <div class="flex flex-wrap items-start justify-between gap-3">
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-center gap-2">
                    <span class="text-sm font-medium">{{
                      queueLabel(job)
                    }}</span>
                    <span
                      class="rounded border border-surface-300 px-1.5 py-0.5 font-mono text-[11px] dark:border-surface-600"
                    >
                      {{ job.id }}
                    </span>
                  </div>
                  <div
                    class="mt-1 break-all font-mono text-xs text-surface-600 dark:text-surface-300"
                  >
                    {{ job.targetUrl }}
                  </div>
                  <div class="mt-2 break-words text-sm">{{ job.message }}</div>
                </div>

                <div
                  class="w-full text-xs text-surface-500 dark:text-surface-400 sm:w-auto sm:text-right"
                >
                  <div>
                    {{ job.requestsSent }} / {{ job.maxRequests }} requests
                  </div>
                  <div>{{ job.discoveredCount }} entries</div>
                  <div>{{ new Date(job.updatedAt).toLocaleTimeString() }}</div>
                </div>
              </div>

              <div v-if="isStoppable(job)" class="mt-3">
                <button
                  class="rounded-md border border-surface-300 bg-surface-0 px-3 py-1.5 text-xs dark:border-surface-600 dark:bg-surface-900"
                  type="button"
                  @click="stopJob(job.id)"
                >
                  Stop scan
                </button>
              </div>

              <div
                v-if="showProgressBar(job)"
                class="mt-3 h-2 overflow-hidden rounded bg-surface-200 dark:bg-surface-700"
              >
                <div
                  class="h-full bg-surface-600 transition-[width] dark:bg-surface-300"
                  :style="{ width: `${requestProgress(job)}%` }"
                />
              </div>

              <div
                v-if="job.result || job.partialEntries.length > 0"
                class="mt-3 grid gap-3 rounded-md border border-surface-200 p-3 text-sm dark:border-surface-700"
              >
                <div class="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div class="font-medium">
                      {{
                        job.result
                          ? job.result.vulnerable
                            ? "Likely vulnerable"
                            : "Not confirmed"
                          : "Partial results"
                      }}
                    </div>
                    <div class="mt-1 text-surface-600 dark:text-surface-300">
                      {{
                        job.result
                          ? job.result.reason
                          : "Confirmed shortnames are shown here as the scan progresses."
                      }}
                    </div>
                  </div>
                  <div
                    class="w-full text-xs text-surface-500 dark:text-surface-400 sm:w-auto sm:text-right"
                  >
                    <div>{{ visibleEntries(job).length }} shortnames</div>
                    <div v-if="job.result">
                      {{
                        job.result.findingCreated
                          ? "finding created"
                          : "finding not created"
                      }}
                    </div>
                  </div>
                </div>

                <div
                  v-if="job.result?.detection"
                  class="grid gap-2 md:grid-cols-2"
                >
                  <div>
                    Method:
                    <span class="font-mono">{{
                      job.result.detection.method
                    }}</span>
                  </div>
                  <div>
                    Suffix:
                    <span class="font-mono">{{
                      job.result.detection.suffix
                    }}</span>
                  </div>
                </div>

                <div class="overflow-auto">
                  <table class="min-w-[52rem] text-left text-xs lg:min-w-full">
                    <thead
                      class="border-b border-surface-200 dark:border-surface-700"
                    >
                      <tr>
                        <th class="px-2 py-1.5 font-medium">Type</th>
                        <th class="px-2 py-1.5 font-medium">Shortname</th>
                        <th class="px-2 py-1.5 font-medium">Base len</th>
                        <th class="px-2 py-1.5 font-medium">Ext</th>
                        <th class="px-2 py-1.5 font-medium">Ext len</th>
                        <th class="px-2 py-1.5 font-medium">URL</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr
                        v-for="entry in visibleEntries(job)"
                        :key="`${entry.kind}:${entry.shortName}`"
                        class="border-b border-surface-200 last:border-b-0 dark:border-surface-700"
                      >
                        <td class="px-2 py-1.5">{{ entry.kind }}</td>
                        <td class="px-2 py-1.5 font-mono">
                          {{ entry.shortName }}
                        </td>
                        <td class="px-2 py-1.5 font-mono">
                          {{ entry.baseLength }}
                        </td>
                        <td class="px-2 py-1.5 font-mono">
                          {{ entry.extension ?? "-" }}
                        </td>
                        <td class="px-2 py-1.5 font-mono">
                          {{ entry.extensionLength || "-" }}
                        </td>
                        <td class="px-2 py-1.5 font-mono break-all">
                          {{ entry.url }}
                        </td>
                      </tr>
                      <tr v-if="visibleEntries(job).length === 0">
                        <td
                          colspan="6"
                          class="px-2 py-3 text-center text-surface-500 dark:text-surface-400"
                        >
                          No shortnames confirmed.
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </article>
          </div>
        </section>
      </div>
    </div>
  </div>
</template>
