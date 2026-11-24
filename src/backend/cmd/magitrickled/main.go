//go:build linux || darwin
// +build linux darwin

// MagiTrickle ориентирован на Linux/Darwin-роутеры и использует netfilter,
// unix-сокеты и платформенные системные вызовы. Сборка под Windows не
// поддерживается и намеренно запрещена этим build-constraint.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"magitrickle"
	"magitrickle/constant"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func getPIDPath(pid int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}

// normalizeExePath убирает суффикс " (deleted)", которым ядро помечает
// /proc/<pid>/exe, когда файл на диске был заменён (unlink+create/rename)
// уже ПОСЛЕ того как процесс с ним заэкзекался — ровно так opkg кладёт новый
// бинарник поверх ещё живого демона. Без нормализации ещё живой старый
// процесс перестаёт опознаваться как "тот же бинарник".
func normalizeExePath(p string) string {
	return strings.TrimSuffix(p, " (deleted)")
}

// sameBinary сравнивает базовые имена двух путей к исполняемому файлу
// (см. normalizeExePath) — так же, как это дальше делает checkPIDFile.
func sameBinary(a, b string) bool {
	return path.Base(normalizeExePath(a)) == path.Base(normalizeExePath(b))
}

func checkPIDFile() (int, error) {
	data, err := os.ReadFile(constant.PIDPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	pid, err := strconv.Atoi(string(data))
	if err != nil {
		return 0, nil
	}

	currPID, _ := getPIDPath(os.Getpid())
	filePID, _ := getPIDPath(pid)
	if sameBinary(currPID, filePID) {
		return pid, nil
	}

	_ = os.Remove(constant.PIDPath)
	return 0, nil
}

func createPIDFile() error {
	pid := os.Getpid()
	return os.WriteFile(constant.PIDPath, []byte(strconv.Itoa(pid)), 0644)
}

func removePIDFile() {
	_ = os.Remove(constant.PIDPath)
}

func parseLogLevel() zerolog.Level {
	for i, arg := range os.Args[1:] {
		if arg == "--" {
			break
		}
		var value string
		if arg == "--log-level" && i+1 < len(os.Args[1:]) {
			value = os.Args[i+2]
		} else if strings.HasPrefix(arg, "--log-level=") {
			value = strings.TrimPrefix(arg, "--log-level=")
		} else {
			continue
		}
		level, err := zerolog.ParseLevel(strings.ToLower(value))
		if err != nil {
			log.Fatal().Str("level", value).Msg("unknown log level (use: trace, debug, info, warn, error)")
		}
		return level
	}
	return zerolog.InfoLevel
}

type consoleLogWriter struct {
	stdout zerolog.ConsoleWriter
	stderr zerolog.ConsoleWriter
}

func (w consoleLogWriter) Write(p []byte) (int, error) {
	return w.stdout.Write(p)
}

func (w consoleLogWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	// OpenWrt procd помечает все строки из stderr как ошибки syslog.
	switch level {
	case zerolog.ErrorLevel, zerolog.FatalLevel, zerolog.PanicLevel:
		return w.stderr.Write(p)
	default:
		return w.Write(p)
	}
}

func newConsoleLogWriter(stdout, stderr io.Writer) consoleLogWriter {
	console := zerolog.ConsoleWriter{
		Out:        stdout,
		TimeFormat: "15:04:05",
		FieldsOrder: []string{
			"id", "net", "name", "client",
			"qclass", "qtype", "rcode",
			"address", "ttl", "cname",
			"group", "groupId", "subnet",
		},
	}
	errorConsole := console
	errorConsole.Out = stderr
	return consoleLogWriter{stdout: console, stderr: errorConsole}
}

func main() {
	zerolog.SetGlobalLevel(parseLogLevel())

	log.Logger = log.Output(newConsoleLogWriter(os.Stdout, os.Stderr))
	startLog := log.Info().Str("version", constant.Version)
	if constant.BuildDate != "" {
		startLog = startLog.Str("build", constant.BuildDate)
	}
	startLog.Msg("starting MagiTrickle daemon")

	pid, err := checkPIDFile()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to check PID file")
	}
	if pid != 0 {
		log.Fatal().Msg(fmt.Sprintf("process %d is already running", pid))
	}

	if err := createPIDFile(); err != nil {
		log.Fatal().Err(err).Msg("failed to create PID file")
	}
	defer removePIDFile()

	app, err := magitrickle.New()
	if err != nil {
		log.Error().Err(err).Msg("refusing to start")
		removePIDFile()
		os.Exit(1)
	}

	log.Info().Msg("starting service")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Запуск ядра приложения в горутине
	appResult := make(chan error, 1)
	go func() {
		appResult <- app.Start(ctx)
	}()

	// Обработка системных сигналов для graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	var once sync.Once
	shutdown := func() {
		log.Info().Msg("shutting down service")
		cancel()
	}

	for {
		select {
		case err := <-appResult:
			if err != nil {
				log.Error().Err(err).Msg("failed to start application")
			}
			once.Do(shutdown)
			log.Info().Msg("service stopped")
			if err != nil {
				removePIDFile()
				os.Exit(1)
			}
			return
		case sig := <-sigChan:
			log.Info().Msgf("received signal: %v", sig)
			switch sig {
			case os.Interrupt, syscall.SIGTERM:
				once.Do(shutdown)
			case syscall.SIGHUP:
				if err := app.LoadConfig(); err != nil {
					log.Error().Err(err).Msg("failed to reload config")
				}
			}
		}
	}
}
