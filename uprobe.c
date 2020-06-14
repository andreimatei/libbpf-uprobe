#include <argp.h>
#include <stdbool.h>
#include <sys/resource.h>  // for rlimit
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <uprobe.skel.h>
#include <linux/perf_event.h>
#include <unistd.h>
#include <sys/syscall.h>

static struct env {
	bool verbose;
} env = {};

const char argp_program_doc[] = "uprobe test\n";
static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};

/* counts, stackmap */
static int map_fd[2];
struct bpf_program *prog;


static int bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	return setrlimit(RLIMIT_MEMLOCK, &rlim_new);
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

#define SAMPLE_FREQ 1 
 
int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

#define TASK_COMM_LEN 16

struct key_t {
	char comm[TASK_COMM_LEN];
	__u32 kernstack;
	__u32 userstack;
};

/*
static void print_ksym(__u64 addr)
{
	struct ksym *sym;

	if (!addr)
		return;
	sym = ksym_search(addr);
	if (!sym) {
		printf("ksym not found. Is kallsyms loaded?\n");
		return;
	}

	printf("%s;", sym->name);
	if (!strstr(sym->name, "sys_read"))
		sys_read_seen = true;
	else if (!strstr(sym->name, "sys_write"))
		sys_write_seen = true;
}
*/

static void print_addr(__u64 addr)
{
	if (!addr)
		return;
	printf("%llx;", addr);
}

static void err_exit(int err)
{
	exit(err);
}

static void print_stack(struct key_t *key, __u64 count)
{
	__u64 ip[PERF_MAX_STACK_DEPTH] = {};
	static bool warned;
	int i;

  /*
	printf("%3lld %s;", count, key->comm);
	if (bpf_map_lookup_elem(map_fd[1], &key->kernstack, ip) != 0) {
		printf("---;");
	} else {
		for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--)
			print_ksym(ip[i]);
	}
	printf("-;");
  */
	if (bpf_map_lookup_elem(map_fd[1], &key->userstack, ip) != 0) {
		printf("---;");
	} else {
		for (i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--)
			print_addr(ip[i]);
	}
	if (count < 6)
		printf("\r");
	else
		printf("\n");

	if (key->kernstack == -EEXIST && !warned) {
		printf("stackmap collisions seen. Consider increasing size\n");
		warned = true;
	} else if ((int)key->kernstack < 0 && (int)key->userstack < 0) {
		printf("err stackid %d %d\n", key->kernstack, key->userstack);
	}
}

static void print_stacks(void)
{
	struct key_t key = {}, next_key;
	__u64 value;
	__u32 stackid = 0, next_id;
	int fd = map_fd[0], stack_map = map_fd[1];

  /*
  bool sys_read_seen, sys_write_seen;
	sys_read_seen = sys_write_seen = false;
  */
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &value);
		print_stack(&next_key, value);
		bpf_map_delete_elem(fd, &next_key);
		key = next_key;
	}
	printf("\n");
  /*
	if (!sys_read_seen || !sys_write_seen) {
		printf("BUG kernel stack doesn't contain sys_read() and sys_write()\n");
		err_exit(error);
	}
  */

	/* clear stack map */
	while (bpf_map_get_next_key(stack_map, &stackid, &next_id) == 0) {
		bpf_map_delete_elem(stack_map, &next_id);
		stackid = next_id;
	}
}

static void test_perf_event(struct perf_event_attr *attr, struct bpf_program *prog)
{
	struct bpf_link *link;
	int pmu_fd, error = 1;

	/* system wide perf event, no need to inherit */
	attr->inherit = 0;

	/* open perf_event on all cpus */

	pmu_fd = syscall(__NR_perf_event_open, attr, -1 /* pid */, 0 /* cpu */, -1 /* group_fd */, 0 /* flags */);
  if (pmu_fd < 0) {
    printf("sys_perf_event_open failed\n");
    goto all_cpu_err;
  }
  link = bpf_program__attach_perf_event(prog, pmu_fd);
  if (libbpf_get_error(&link)) {
    printf("bpf_program__attach_perf_event failed\n");
    link = NULL;
    close(pmu_fd);
    goto all_cpu_err;
  }

  sleep(100);
  printf("done sleeping. printing stacks\n");

	print_stacks();
	error = 0;
all_cpu_err:
  // !!! bpf_link__destroy(link);
	// !!! free(link);
	if (error)
		err_exit(error);
}


int main(int argc, char **argv) {
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	int err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err) return err;


	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}

	struct uprobe_bpf* obj;
	obj = uprobe_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

  printf("about to configure skeleton\n");
	/* initialize global data */
	obj->rodata->cfg.x = 42;

 	/* load BPF program */
	if (uprobe_bpf__load(obj)) {
		printf("loading BPF object file failed\n");
    return 1;
	}

  // bpf_program__attach_uprobe
  // bpf_program__attach_perf_event
  // sample for attaching to perf event:
  // https://github.com/torvalds/linux/blob/9aa900c8094dba7a60dc805ecec1e9f720744ba1/samples/bpf/trace_event_user.c#L137

 	struct perf_event_attr attr_type_sw = {
		.sample_freq = SAMPLE_FREQ,
		.freq = 1,
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};

  /*
  prog = bpf_object__find_program_by_name(obj, "bpf_timer");
	if (!prog) {
		printf("finding a prog in obj file failed\n");
	}
  */
  struct bpf_program* timer_prog;
  timer_prog = obj->progs.bpf_timer;

  test_perf_event(&attr_type_sw, timer_prog);

  return 0;
}
