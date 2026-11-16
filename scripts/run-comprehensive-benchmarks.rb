#!/usr/bin/env ruby
# frozen_string_literal: true

# Runs the benchmark matrix for `POST /v1/sign` and saves the results.
#
# The script runs `benches/custom_benchmark.rs` once for each configuration
# below. The benchmark starts its own copy of the service, with the settings
# that this script puts in the environment. The script runs these groups, in
# this order:
#
#   1. baseline:  one session (no pool), no queue limit in practice
#   2. pools:     session pool sizes 2, 5, 10 and 20 at every concurrency level
#   3. timeouts:  pool size 20, 500 callers, with different values of
#                 HSM_SIGNING_SERVICE_POOL_CONNECTION_TIMEOUT_MS
#   4. queue:     pool size 20, 500 callers, HSM_SIGNING_SERVICE_MAX_QUEUE=400
#
# The results go to `target/bench-results/<MMDDYYhhmm>/`. The script overwrites
# files that exist. Each run has a `.txt` file with the raw output of the
# benchmark. The script also writes `results.json`, `results.csv` and
# `metadata.json`.
#
# The service uses the real token and the PIN of the developer. Load `.envrc`
# first (for example with `direnv allow`, or `set -a; . ./.envrc; set +a`).
# The script never prints the PIN.
#
#   scripts/run-comprehensive-benchmarks
#   scripts/run-comprehensive-benchmarks --warmup-secs 1 --duration-secs 3
#   scripts/run-comprehensive-benchmarks --dry-run

require 'fileutils'
require 'json'
require 'optparse'
require 'time'

ROOT = File.expand_path('..', __dir__)

CONCURRENCY = [1, 10, 100, 500].freeze
POOL_SIZES = [2, 5, 10, 20].freeze

# The timeouts that the request asked for, in milliseconds.
TIMEOUTS_MS = [500, 1000].freeze
# Smaller timeouts, to show the effect of the timeout on the errors. With the
# values above, the waits for a session are shorter than the timeout.
EXTRA_TIMEOUTS_MS = [200, 100, 50].freeze

# A queue length that never limits the benchmark: the largest number of
# callers is 500.
UNLIMITED_QUEUE = 1000
# A timeout that never expires in the benchmark.
LONG_TIMEOUT_MS = 5000
# The queue length for the queue demonstration: with a pool of 20 sessions,
# the service has 420 places for 500 callers.
LIMITED_QUEUE = 400

SEED = 42

REQUIRED_ENV = %w[PKCS11_MODULE HSM_PIN HSM_TOKEN_LABEL].freeze
SERVICE_ENV = %w[
  HSM_SIGNING_SERVICE_SESSION_POOL_SIZE
  HSM_SIGNING_SERVICE_POOL_CONNECTION_TIMEOUT_MS
  HSM_SIGNING_SERVICE_MAX_QUEUE
].freeze

# One benchmark process: a service configuration and the concurrency levels
# that run against it.
Run = Struct.new(:name, :group, :description, :pool_size, :timeout_ms, :max_queue, :concurrency,
                 keyword_init: true) do
  # The environment for the child process. A value of `nil` removes the
  # variable, so a value from `.envrc` cannot change the run.
  def env
    {
      'HSM_SIGNING_SERVICE_SESSION_POOL_SIZE' => pool_size&.to_s,
      'HSM_SIGNING_SERVICE_POOL_CONNECTION_TIMEOUT_MS' => timeout_ms&.to_s,
      'HSM_SIGNING_SERVICE_MAX_QUEUE' => max_queue.to_s
    }
  end
end

def build_runs
  runs = []

  runs << Run.new(
    name: 'baseline_single_session', group: 'baseline',
    description: 'One session, no pool, no queue limit in practice',
    pool_size: nil, timeout_ms: nil, max_queue: UNLIMITED_QUEUE, concurrency: CONCURRENCY
  )

  POOL_SIZES.each do |size|
    runs << Run.new(
      name: "pool_#{size}", group: 'pools',
      description: "Session pool of #{size}, timeout #{LONG_TIMEOUT_MS} ms, no queue limit in practice",
      pool_size: size, timeout_ms: LONG_TIMEOUT_MS, max_queue: UNLIMITED_QUEUE,
      concurrency: CONCURRENCY
    )
  end

  (TIMEOUTS_MS + EXTRA_TIMEOUTS_MS).each do |ms|
    runs << Run.new(
      name: "timeout_#{ms}ms", group: 'timeouts',
      description: "Session pool of 20, timeout #{ms} ms, no queue limit in practice",
      pool_size: 20, timeout_ms: ms, max_queue: UNLIMITED_QUEUE, concurrency: [500]
    )
  end

  runs << Run.new(
    name: "queue_#{LIMITED_QUEUE}", group: 'queue',
    description: "Session pool of 20, timeout #{LONG_TIMEOUT_MS} ms, queue of #{LIMITED_QUEUE}",
    pool_size: 20, timeout_ms: LONG_TIMEOUT_MS, max_queue: LIMITED_QUEUE, concurrency: [500]
  )

  runs
end

# Parse the output of the benchmark into one hash for each concurrency level.
def parse_output(text)
  text.split(/^== (\d+) concurrent callers ==$/)[1..].each_slice(2).map do |callers, body|
    requests = body.match(/^requests: (\d+) \(ok (\d+), errors (\d+)\)$/)
    latency = body.match(
      /^latency ms: min ([\d.]+)\s+p50 ([\d.]+)\s+p95 ([\d.]+)\s+p99 ([\d.]+)\s+max ([\d.]+)$/
    )
    {
      'concurrency' => callers.to_i,
      'requests' => requests && requests[1].to_i,
      'ok' => requests && requests[2].to_i,
      'errors' => requests && requests[3].to_i,
      'error_rate_percent' => body[/^error rate: ([\d.]+)%$/, 1]&.to_f,
      'throughput_rps' => body[/^throughput: ([\d.]+) req\/s$/, 1]&.to_f,
      'min_ms' => latency && latency[1].to_f,
      'p50_ms' => latency && latency[2].to_f,
      'p95_ms' => latency && latency[3].to_f,
      'p99_ms' => latency && latency[4].to_f,
      'max_ms' => latency && latency[5].to_f
    }
  end
end

def capture(*command)
  out = IO.popen(command, chdir: ROOT, err: File::NULL, &:read)
  out.to_s.strip
rescue SystemCallError
  ''
end

def metadata(options, stamp)
  {
    'started_at' => Time.now.iso8601,
    'directory' => stamp,
    'git_commit' => capture('git', 'rev-parse', '--short', 'HEAD'),
    'git_dirty' => !capture('git', 'status', '--porcelain').empty?,
    'rustc' => capture('rustc', '--version'),
    'cpu' => capture('sysctl', '-n', 'machdep.cpu.brand_string'),
    'cpu_cores' => capture('sysctl', '-n', 'hw.ncpu').to_i,
    'os' => capture('uname', '-sr'),
    'softhsm' => capture('softhsm2-util', '--version'),
    'warmup_secs' => options[:warmup_secs],
    'duration_secs' => options[:duration_secs],
    'seed' => SEED,
    'unlimited_queue' => UNLIMITED_QUEUE,
    'long_timeout_ms' => LONG_TIMEOUT_MS
  }
end

def write_csv(path, results)
  header = %w[run group pool_size timeout_ms max_queue concurrency requests ok errors
              error_rate_percent throughput_rps min_ms p50_ms p95_ms p99_ms max_ms]
  File.open(path, 'w') do |file|
    file.puts(header.join(','))
    results.each do |run|
      run['levels'].each do |level|
        file.puts(
          [run['name'], run['group'], run['pool_size'], run['timeout_ms'], run['max_queue'],
           *level.values_at('concurrency', 'requests', 'ok', 'errors', 'error_rate_percent',
                            'throughput_rps', 'min_ms', 'p50_ms', 'p95_ms', 'p99_ms', 'max_ms')].join(',')
        )
      end
    end
  end
end

options = { warmup_secs: 5, duration_secs: 30, dry_run: false }
OptionParser.new do |parser|
  parser.banner = 'Usage: scripts/run-comprehensive-benchmarks [options]'
  parser.on('--warmup-secs N', Integer, 'Warm-up of each level (default 5)') { |n| options[:warmup_secs] = n }
  parser.on('--duration-secs N', Integer, 'Measured time of each level (default 30)') { |n| options[:duration_secs] = n }
  parser.on('--dry-run', 'Show the runs and stop') { options[:dry_run] = true }
end.parse!

runs = build_runs
level_count = runs.sum { |run| run.concurrency.size }
seconds = level_count * (options[:warmup_secs] + options[:duration_secs])
puts "#{runs.size} runs, #{level_count} levels, about #{(seconds / 60.0).ceil} minutes of measuring"

if options[:dry_run]
  runs.each do |run|
    puts format('  %-26s pool=%-4s timeout=%-5s queue=%-5s callers=%s',
                run.name, run.pool_size || '-', run.timeout_ms || '-', run.max_queue,
                run.concurrency.join(','))
  end
  exit
end

missing = REQUIRED_ENV.reject { |name| ENV.key?(name) }
unless missing.empty?
  abort "Not set: #{missing.join(', ')}. Load .envrc first (direnv allow, or: set -a; . ./.envrc; set +a)."
end

stamp = Time.now.strftime('%m%d%y%H%M')
out_dir = File.join(ROOT, 'target', 'bench-results', stamp)
FileUtils.mkdir_p(out_dir)
puts "Results: #{out_dir}"

puts 'Building the benchmark...'
system('cargo', 'bench', '--bench', 'custom_benchmark', '--no-run', chdir: ROOT) || abort('Build failed.')

File.write(File.join(out_dir, 'metadata.json'), JSON.pretty_generate(metadata(options, stamp)))

results = []
runs.each_with_index do |run, index|
  puts format('[%d/%d] %s: %s (callers %s)', index + 1, runs.size, run.name, run.description,
              run.concurrency.join(','))
  txt = File.join(out_dir, "#{run.name}.txt")
  # The benchmark inherits the environment, so it gets the token, the key
  # label and the PIN from the shell. Remove every other service setting that
  # the shell may have.
  env = SERVICE_ENV.to_h { |name| [name, nil] }.merge(run.env)
  command = ['cargo', 'bench', '--bench', 'custom_benchmark', '--',
             '--warmup-secs', options[:warmup_secs].to_s,
             '--duration-secs', options[:duration_secs].to_s,
             '--seed', SEED.to_s,
             '-C', run.concurrency.join(',')]
  ok = system(env, *command, chdir: ROOT, out: [txt, 'w'], err: %i[child out])
  text = File.read(txt)
  levels = parse_output(text)
  warn "  the run failed or printed no results; see #{txt}" if !ok || levels.size != run.concurrency.size
  levels.each do |level|
    puts format('  %4d callers: %8s req/s  p50 %s ms  p99 %s ms  errors %s (%s%%)',
                level['concurrency'], level['throughput_rps'] || '-', level['p50_ms'] || '-',
                level['p99_ms'] || '-', level['errors'], level['error_rate_percent'])
  end
  results << run.to_h.slice(:name, :group, :description, :pool_size, :timeout_ms, :max_queue)
                 .transform_keys(&:to_s).merge('success' => ok, 'levels' => levels)
  # Save after each run, so a stop in the middle keeps the finished runs.
  File.write(File.join(out_dir, 'results.json'), JSON.pretty_generate(results))
  write_csv(File.join(out_dir, 'results.csv'), results)
end

puts "Done. Results: #{out_dir}"
