#include <argp.h>

struct env {
    time_t interval;
	pid_t pid;
	int times;
	bool verbose;
} env = {
	.interval = 99999999,
	.times = 99999999,
};

static volatile bool exiting;

const char argp_program_doc[] =
"ebpf_program Description...\n"
"\n"
"USAGE: ebpf_program [--help] [parms]\n"
"\n"
"EXAMPLES:\n"
"    ebpf_program\n";

// struct argp_option {
//   const char *name;
//   int key;
//   const char *arg;
//   int flags;
//   const char *doc;
//   int group;
// };
static const struct argp_option opts[] = {
	{ "Desc.", 'd', NULL, 0, "doc..." },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	static int pos_args;

	switch (key) {
	case 'd':
		env.test = 0;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'v':
		env.verbose = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

// usage
int main(int argc, char *argv[])
{
    /* code */
    int err;
    static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	if (err = argp_parse(&argp, argc, argv, 0, NULL, NULL))
		return err;
    return 0;
}
