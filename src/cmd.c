// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "cmd.h"
#include "utils.h"

#define FD_READ     0
#define FD_WRITE    1
#define ERR_NOT_FOUND 127
#define ERR_NO_PERM   126

/**
 * Internal change-directory command.
 */
static int shell_cd(word_t *dir)
{
	/* Verificam daca avem argumente invalide */
	if (dir == NULL || dir->next_word != NULL)
		return 0;

	char *target_dir = get_word(dir);

	if (!target_dir)
		return 0;

	int status = chdir(target_dir);

	if (status < 0)
		perror(target_dir);

	free(target_dir);
	return status;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* Returnam codul special pentru inchiderea shell-ului */
	return SHELL_EXIT;
}

/**
 * Internal pwd command.
 */
static int shell_pwd(void)
{
	char buffer[4096];
	char *result = getcwd(buffer, sizeof(buffer));

	if (result) {
		printf("%s\n", result);
		/* Trebuie sa facem flush pentru a trata corect redirectarile */
		fflush(stdout);
		return 0;
	}
	perror("shell_pwd");
	return 1;
}

/**
 * Functie helper pentru gestionarea redirectarilor.
 */
static int handle_redirections(simple_command_t *s, int *orig_in, int *orig_out, int *orig_err)
{
	/* Salvam descriptorii standard daca se cere */
	if (orig_in)
		*orig_in = dup(STDIN_FILENO);
	if (orig_out)
		*orig_out = dup(STDOUT_FILENO);
	if (orig_err)
		*orig_err = dup(STDERR_FILENO);
	/* 1. Redirectare intrare (<) */
	if (s->in) {
		char *fname = get_word(s->in);
		int fin = open(fname, O_RDONLY);

		if (fin < 0) {
			fprintf(stderr, "Eroare la deschiderea fisierului de intrare: %s\n", fname);
			free(fname);
			return -1;
		}
		dup2(fin, STDIN_FILENO);
		close(fin);
		free(fname);
	}

	char *fout_name = NULL;
	char *ferr_name = NULL;
	int fd_curr = -1;
	/* Extragem numele fisierelor pentru output si error */
	if (s->out)
		fout_name = get_word(s->out);
	if (s->err)
		ferr_name = get_word(s->err);
	/* 2. Redirectare iesire (>, >>, &>) */
	if (fout_name) {
		int mode = O_WRONLY | O_CREAT;
		/* Verificam flag-ul de append */
		mode |= (s->io_flags & IO_OUT_APPEND) ? O_APPEND : O_TRUNC;
		fd_curr = open(fout_name, mode, 0644);
		if (fd_curr < 0) {
			fprintf(stderr, "Eroare la deschiderea fisierului de iesire: %s\n", fout_name);
			free(fout_name);
			if (ferr_name)
				free(ferr_name);
			return -1;
		}
		dup2(fd_curr, STDOUT_FILENO);
	}
	/* 3. Redirectare eroare (2>, 2>>, &>) */
	if (ferr_name) {
		/* Cazul special &> unde fisierul e acelasi */
		if (fout_name && strcmp(fout_name, ferr_name) == 0) {
			dup2(fd_curr, STDERR_FILENO);
		} else {
			int mode = O_WRONLY | O_CREAT;

			mode |= (s->io_flags & IO_ERR_APPEND) ? O_APPEND : O_TRUNC;

			int fderr = open(ferr_name, mode, 0644);

			if (fderr < 0) {
				fprintf(stderr, "Eroare la deschiderea fisierului de eroare: %s\n", ferr_name);
				if (fout_name)
					free(fout_name);
				free(ferr_name);
				if (fd_curr >= 0)
					close(fd_curr);
				return -1;
			}
			dup2(fderr, STDERR_FILENO);
			close(fderr);
		}
	}
	if (fd_curr >= 0)
		close(fd_curr);
	if (fout_name)
		free(fout_name);
	if (ferr_name)
		free(ferr_name);

	return 0;
}
/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	if (!s)
		return 0;

	char *cmd_str = get_word(s->verb);
	int exit_status = 0;

	/* Identificam tipul comenzii */
	enum { CMD_NONE, CMD_EXIT, CMD_CD, CMD_PWD, CMD_VAR } type = CMD_NONE;
	if (strcmp(cmd_str, "exit") == 0 || strcmp(cmd_str, "quit") == 0)
		type = CMD_EXIT;
	else if (strcmp(cmd_str, "cd") == 0)
		type = CMD_CD;
	else if (strcmp(cmd_str, "pwd") == 0)
		type = CMD_PWD;
	else if (strchr(cmd_str, '='))
		type = CMD_VAR;

	if (type != CMD_NONE) {
		int stdin_dup = -1, stdout_dup = -1, stderr_dup = -1;
		/* Aplicam redirectarile pentru built-ins */
		if (handle_redirections(s, &stdin_dup, &stdout_dup, &stderr_dup) < 0) {
			free(cmd_str);
			return 1;
		}

			switch (type) {
			case CMD_EXIT:
				free(cmd_str);
				exit_status = shell_exit();
				break;
			case CMD_CD:
				exit_status = shell_cd(s->params);
				free(cmd_str);
				break;
			case CMD_PWD:
				exit_status = shell_pwd();
				free(cmd_str);
				break;
			case CMD_VAR: {
				char *delim = strchr(cmd_str, '=');

				if (delim) {
					*delim = 0;
					exit_status = setenv(cmd_str, delim + 1, 1);
				}
				free(cmd_str);
				break;
			}
			default:
				break;
		}

		/* Restauram descriptorii */
		if (stdin_dup != -1) {
			dup2(stdin_dup, STDIN_FILENO);
			close(stdin_dup);
		}
		if (stdout_dup != -1) {
			dup2(stdout_dup, STDOUT_FILENO);
			close(stdout_dup);
		}
		if (stderr_dup != -1) {
			dup2(stderr_dup, STDERR_FILENO);
			close(stderr_dup);
		}

		return exit_status;
	}

	/* Comanda Externa */
	pid_t child = fork();

	if (child < 0) {
		perror("Eroare la fork");
		free(cmd_str);
		return 1;
	}

	if (child == 0) {
		/* Procesul copil */
		if (handle_redirections(s, NULL, NULL, NULL) < 0) {
			free(cmd_str);
			exit(1);
		}

		int argc = 0;
		char **argv = get_argv(s, &argc);

		execvp(cmd_str, argv);

		/* Daca ajungem aici, exec a esuat */
		fprintf(stderr, "Execution failed for '%s'\n", cmd_str);
		int code = 1;

		if (errno == ENOENT)
			code = ERR_NOT_FOUND;
		else if (errno == EACCES)
			code = ERR_NO_PERM;
		/* Eliberam resursele in copil */
		free(cmd_str);
		for (int i = 0; i < argc; i++)
			free(argv[i]);
		free(argv);
		exit(code);
	}

	/* Procesul parinte */
	free(cmd_str);
	int status;

	waitpid(child, &status, 0);

	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);

	return 0;
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	pid_t worker = fork();

	if (worker < 0)
		return 1;

	if (worker == 0) {
		/* Copilul executa prima comanda si iese */
		int code = parse_command(cmd1, level + 1, father);

		exit(code);
	}

	/* Parintele executa a doua comanda in paralel */
	return parse_command(cmd2, level + 1, father);
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int pfd[2];

	if (pipe(pfd) < 0)
		return 1;

	pid_t c1 = fork();

	if (c1 < 0) {
		close(pfd[FD_READ]); close(pfd[FD_WRITE]);
		return 1;
	}

	if (c1 == 0) {
		/* Configurare capat scriere pentru primul copil */
		close(pfd[FD_READ]);
		dup2(pfd[FD_WRITE], STDOUT_FILENO);
		close(pfd[FD_WRITE]);
		int res = parse_command(cmd1, level + 1, father);

		exit(res);
	}

	pid_t c2 = fork();

	if (c2 < 0) {
		close(pfd[FD_READ]); close(pfd[FD_WRITE]);
		waitpid(c1, NULL, 0);
		return 1;
	}

	if (c2 == 0) {
		/* Configurare capat citire pentru al doilea copil */
		close(pfd[FD_WRITE]);
		dup2(pfd[FD_READ], STDIN_FILENO);
		close(pfd[FD_READ]);
		int res = parse_command(cmd2, level + 1, father);

		exit(res);
	}

	/* Inchidem pipe-ul in parinte si asteptam copiii */
	close(pfd[FD_READ]);
	close(pfd[FD_WRITE]);

	int s1, s2;

	waitpid(c1, &s1, 0);
	waitpid(c2, &s2, 0);

	if (WIFEXITED(s2))
		return WEXITSTATUS(s2);
	return 0;
}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	if (c == NULL)
		return 0;

	/* Cazul de baza: comanda simpla */
	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level, father);

	int result = 0;

		switch (c->op) {
		case OP_SEQUENTIAL:
			/* Executie secventiala (;) */
			result = parse_command(c->cmd1, level + 1, c);
			if (result == SHELL_EXIT)
				return SHELL_EXIT;
			result = parse_command(c->cmd2, level + 1, c);
			break;

		case OP_PARALLEL:
			/* Executie paralela (&) */
			result = run_in_parallel(c->cmd1, c->cmd2, level + 1, c);
			break;

		case OP_CONDITIONAL_NZERO:
			/* Operatorul || */
			result = parse_command(c->cmd1, level + 1, c);
			if (result == SHELL_EXIT)
				return SHELL_EXIT;
			if (result != 0)
				result = parse_command(c->cmd2, level + 1, c);
			break;

		case OP_CONDITIONAL_ZERO:
			/* Operatorul && */
			result = parse_command(c->cmd1, level + 1, c);
			if (result == SHELL_EXIT)
				return SHELL_EXIT;
			if (result == 0)
				result = parse_command(c->cmd2, level + 1, c);
			break;

		case OP_PIPE:
			/* Operatorul | */
			result = run_on_pipe(c->cmd1, c->cmd2, level + 1, c);
			break;

		default:
			return SHELL_EXIT;
	}
	return result;
}
